pub mod manager;
pub mod hd_keys;

pub mod signing_room;

use std::{env, fs, thread, time};
use std::path::Path;
use std::time::{Instant, SystemTime, Duration};

use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use curv::arithmetic::{Zero};
use curv::BigInt;
use std::process::exit;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::Curve;
use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::blocking::Client as RequestClient;
use serde::{Deserialize, Serialize};
use rand::{rngs::OsRng, TryRngCore};
use reqwest::header::{HeaderMap, AUTHORIZATION};
use reqwest::StatusCode;
use sha2::{Sha256, Digest};
use crate::protocols::{ecdsa, eddsa};
use crate::protocols::ecdsa::ECDSAParameters;
use crate::protocols::eddsa::EdDSAParameters;

pub type Key = String;

pub(crate) const MAX_FIRST_PRIMES: usize =  2_i64.pow(25) as usize;
pub(crate) const MANAGER_ERROR_MESSAGE: &str = "Manager returned error";
const INVALID_KEY_LEN_ERROR: &str = "Key length is invalid!";
pub const TSS_CLI_POLL_TIMEOUT_VAR: &str = "TSS_CLI_POLL_TIMEOUT";
const TSS_CLI_POLL_TIMEOUT_DEFAULT: u64 = 30;

#[derive(Clone)]
pub enum DKGSignScheme { ECDSA, EdDSA }

#[derive(Clone)]
pub struct Client {
    client: RequestClient,
    address: String,
    api_key: String,
    secret_key: String,
}

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;
pub const PARTY_HTTP_AUTH_APIKEY_VAR: &str = "TSS_PARTY_JWT_APIKEY";
pub const HTTP_AUTH_JWT_EXPIRY_VAR: &str = "TSS_HTTP_AUTH_JWT_TTL";
pub const HTTP_AUTH_JWT_EXPIRY_DEFAULT: &str = "10";
const HTTP_AUTH_JWT_SECRET_VAR: &str = "TSS_PARTY_JWT_SECRET";
pub const LOG_LEVEL_ENV_VAR: &str = "TSS_LOG_LEVEL";

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignupRequestBody {
    pub threshold: u16,
    pub room_id: String,
    pub party_number: u16,  // It's better to rename this to fragment_index
    pub party_uuid: String,
    pub curve_name: String
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SigningPartySignup {
    pub party_order: u16,
    pub party_uuid: String,
    pub room_uuid: String,
    pub total_joined: u16,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SigningPartyInfo {
    pub party_id: String,
    pub party_order: u16,
    pub last_ping: u64,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ManagerError {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

pub fn error_message(normal_message: &str, debug_message: &str) -> String {
    let log_level = std::env::var(LOG_LEVEL_ENV_VAR).unwrap_or(String::from("production"));
    match log_level.as_str() {
        "debug" => debug_message.to_string(),
        _ => normal_message.to_string()
    }
}

impl Client {
    pub fn new(address: String) -> Self {
        let api_key = env::var(PARTY_HTTP_AUTH_APIKEY_VAR).unwrap_or_else(|_|{
            eprintln!("\x1b[0;33m Missing env variable: {}, requests will be sent as anonymous user.\x1b[0m", PARTY_HTTP_AUTH_APIKEY_VAR);
            "anonymous".to_string()
        });

        let secret_key = env::var(HTTP_AUTH_JWT_SECRET_VAR).unwrap_or_else(|_|{
            println!("\x1b[0;33m Missing env variable: {}, requests will be sent as anonymous user.\x1b[0m", HTTP_AUTH_JWT_SECRET_VAR);
            "anonymous_secret_key".to_string()
        });

        Self {
            client: RequestClient::new(),
            address,
            api_key,
            secret_key,
        }
    }

    fn generate_jwt(&self) -> String {
        let jwt_expiry_seconds = env::var(HTTP_AUTH_JWT_EXPIRY_VAR)
            .unwrap_or(HTTP_AUTH_JWT_EXPIRY_DEFAULT.to_string()).parse::<u64>().unwrap_or_else(|e| {
            println!("Invalid value for env var {}: {}. It must be an integer.", HTTP_AUTH_JWT_EXPIRY_VAR, e);
            exit(1);
        });
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        // Prepare the JWT
        let claims = JwtClaims {
            api_key: self.api_key.clone(), // The subject (party identifier)
            exp: now + jwt_expiry_seconds,
        };

        let mut header = Header::default();
        header.kid = Some(self.api_key.clone());
        let encoding_key = EncodingKey::from_secret(self.secret_key.as_bytes());

        // Encode the JWT and return the token
        match encode(&header, &claims, &encoding_key) {
            Ok(encoded_string) => {encoded_string}
            Err(error) => {
                eprintln!("Error encoding JWT: {}", error);
                exit(1);
            }
        }
    }

}

// Define the claims structure expected in the JWT
#[derive(Debug, Deserialize, Serialize)]
struct JwtClaims {
    api_key: String,
    exp: u64,
}

pub fn validate_hex_string(message: &str) -> bool {
    !message.is_empty() && message.chars().all(|c| c.is_ascii_hexdigit()) &&
        message.len() >= 32
}

pub fn validate_vss_scheme_vector<E: Curve>(vss_scheme_vec: Vec<VerifiableSS<E>>) -> Result<bool, String> {
    for (i, inner_vec) in vss_scheme_vec.iter().enumerate() {
        if inner_vec.commitments.is_empty() {
            return Err(format!("vss_scheme_vec[{}] is an empty vector", i));
        }
        for (j, ge) in inner_vec.commitments.iter().enumerate() {
            if ge.is_zero() {
                return Err(format!("vss_scheme_vec[{}][{}] contains an invalid GE element", i, j));
            }
        }
    }

    Ok(true)
}

pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Result<AEAD, String> {
    if key.len() != AES_KEY_BYTES_LEN {
        return Err(String::from(INVALID_KEY_LEN_ERROR));
    }
    let aes_key = aes_gcm::Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    let _ = OsRng.try_fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");

    Ok(AEAD {
        ciphertext: ciphertext,
        tag: nonce.to_vec(),
    })
}

pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Result<Vec<u8>, String> {
    if key.len() != AES_KEY_BYTES_LEN {
        return Err(String::from(INVALID_KEY_LEN_ERROR));
    }
    let aes_key = aes_gcm::Key::from_slice(key);
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    let out = gcm.decrypt(nonce, aead_pack.ciphertext.as_slice());
    match out {
        Ok(out) => Ok(out),
        Err(error) => Err(error.to_string())
    }
}

pub fn postb<T>(client: &Client, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
{
    let addr = client.address.clone();
    let retries = 3;
    let retry_delay = time::Duration::from_millis(250);
    let jwt_token = client.generate_jwt();

    // Create the headers with the API key
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, format!("Bearer {}", jwt_token).parse().unwrap());

    for i in 1..retries {
        let addr = format!("{}/{}", addr, path);
        let res = client.client.post(&addr)
            .headers(headers.clone())
            .json(&body)
            .send();

        match res {
            Ok(response) => {
                match response.status() {
                    StatusCode::OK => {
                        return Some(response.text().unwrap())
                    }
                    StatusCode::UNAUTHORIZED => {
                        eprintln!("Unauthorized request for {}", addr);
                        return None
                    }
                    other_codes => {
                        if i==retries {
                            eprintln!("{} Retries failed for {} with code {}", retries, addr, other_codes);
                        }
                    }
                }

            },
            Err(error) => {
                if i == retries {
                    eprintln!("Posting data to manager returned an error: {}. Stopped retrying.", error);
                }
                else {
                    eprintln!("Posting data to manager returned an error: {}. Retrying...", error);
                }

            }
        }
        thread::sleep(retry_delay);
    }
    None
}

pub fn broadcast(
    client: &Client,
    party_num: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    let entry = Entry {
        key: key.clone(),
        value: data,
    };
    let res_body = postb(&client, "set", entry).unwrap();
    serde_json::from_str(&res_body).unwrap()
}

pub fn sendp2p(
    client: &Client,
    party_from: u16,
    party_to: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

    let entry = Entry {
        key: key.clone(),
        value: data,
    };

    let res_body = postb(&client, "set", entry).unwrap();
    serde_json::from_str(&res_body).unwrap()
}

pub fn poll_for_broadcasts(
    client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    let timeout = std::env::var(TSS_CLI_POLL_TIMEOUT_VAR)
        .unwrap_or(TSS_CLI_POLL_TIMEOUT_DEFAULT.to_string()).parse::<u64>().unwrap();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, sender_uuid);
            let index = Index { key };
            let start_time = Instant::now();
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);
                let res_body = postb(&client, "get", index.clone()).unwrap();
                let answer: Result<Entry, ManagerError> = serde_json::from_str(&res_body)
                    .unwrap_or_else(|e| {
                        println!("{}", error_message("Error in calling manager",
                                                    format!("Error in calling manager {}", e).as_str())
                        );
                        exit(1);
                    });
                match answer {
                    Ok(answer) => {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    },
                    Err(ManagerError{error: _manager_error}) => {
                        #[cfg(debug_assertions)]
                        println!("[{:?}] party {:?} => party {:?}, error: {:?}", round, i, party_num, _manager_error);
                    }
                }
                if start_time.elapsed().as_secs() > timeout {
                    eprintln!("Polling timed out! No response received from party number {:?}", i);
                    exit(1);
                };

                thread::sleep(delay);
            }
        }
    }
    ans_vec
}

pub fn poll_for_p2p(
    client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    let timeout = env::var(TSS_CLI_POLL_TIMEOUT_VAR)
        .unwrap_or(TSS_CLI_POLL_TIMEOUT_DEFAULT.to_string()).parse::<u64>().unwrap();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
            let index = Index { key };
            let start_time = Instant::now();
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);

                let res_body = postb(&client, "get", index.clone()).unwrap();
                //let res_body = postb(&client, "get", index.clone()).unwrap();
                let answer: Result<Entry, ManagerError> = serde_json::from_str(&res_body).unwrap();
                match answer {
                    Ok(answer) => {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    },
                    Err(ManagerError{error: manager_error}) => {
                        if start_time.elapsed().as_secs() > timeout {
                            panic!("Polling timed out! No response received in {:?} from party number {:?}. Error: {:?}", round, i, manager_error);
                        };
                        #[cfg(debug_assertions)]
                        println!("[{:?}] party {:?} => party {:?}, error: {:?}", round, i, party_num, manager_error);
                    }
                }
            }
        }
    }
    ans_vec
}

pub fn keygen_signup(client: &Client, params: &Params, curve_name: &str) -> (u16, String) {
    match postb(&client, "signupkeygen", (params, curve_name)) {
        Some(res_body) => {
            match serde_json::from_str(&res_body) {
                Ok(result) => {
                    match result {
                        Ok(PartySignup { number, uuid }) => {
                            if number < 1 || number > params.parties.parse::<u16>().unwrap() {
                                println!("Manager returned an invalid party ID: {}", number);
                                exit(1);
                            }
                            (number, uuid)
                        },
                        Err(ManagerError { error }) => {
                            println!("{}: {}", MANAGER_ERROR_MESSAGE, error);
                            exit(1);
                        },
                    }
                },
                Err(error) => {
                    println!("{}: {}", MANAGER_ERROR_MESSAGE, error);
                    exit(1);
                }
            }
        }
        None => {
            println!("Signup returned no response");
            exit(1);
        }
    }
}


pub fn signup(path: &str, client: &Client, params: &Params, room_id: String, party_id: u16, curve_name: &str) -> Result<(PartySignup, u16), ()> {
    let threshold = params.threshold.parse::<u16>().unwrap();
    let mut request_body = PartySignupRequestBody{
        threshold: threshold,
        room_id: room_id.clone(),
        party_number: party_id,
        party_uuid: "".to_string(),
        curve_name: curve_name.to_string()
    };
    let delay = time::Duration::from_millis(100);
    let timeout = std::env::var("TSS_CLI_SIGNUP_TIMEOUT")
        .unwrap_or("30".to_string()).parse::<u64>().unwrap();
    let res_body = postb(&client, path, request_body.clone()).unwrap();
    let answer: Result<SigningPartySignup, ManagerError> = serde_json::from_str(&res_body).unwrap();
    let (output, total_parties) = match answer {
        Ok(SigningPartySignup{party_order, party_uuid, room_uuid, total_joined}) => {
            println!("Signed up, party order: {:?}, joined so far: {:?}, waiting for room uuid", party_order, total_joined);
            let mut now = time::SystemTime::now();
            let mut last_total_joined = total_joined;
            let mut party_signup = PartySignup {
                number: party_order,
                uuid: room_uuid
            };
            while party_signup.uuid.is_empty() {
                thread::sleep(delay);
                request_body.party_uuid = party_uuid.clone();
                let res_body = postb(&client, path, request_body.clone()).unwrap();
                let answer: Result<SigningPartySignup, ManagerError> = serde_json::from_str(&res_body).unwrap();
                match answer {
                    Ok(SigningPartySignup{party_order, party_uuid, room_uuid, total_joined}) => {
                        request_body.party_uuid = party_uuid;
                        if party_signup.number != party_order {
                            println!("Order is changed: {:?}", party_order);
                            party_signup.number = party_order;
                        }
                        party_signup.uuid = room_uuid;
                        if total_joined != last_total_joined {
                            println!("Joined so far: {:?}", total_joined);
                            last_total_joined = total_joined;
                            //Reset the signup timeout
                            now = time::SystemTime::now();
                        }
                    },
                    Err(ManagerError{error}) => {
                        panic!("Manager returned an error in response to signup request: {}", error);
                    }
                };
                if now.elapsed().unwrap().as_secs() > timeout{
                    break;
                }
            }
            if party_signup.uuid.is_empty() {
                panic!("Could not get room uuid after {:?} seconds of tries", timeout);
            }
            (party_signup, last_total_joined)
        },
        Err(ManagerError{error}) => {
            eprintln!("{}: {}", MANAGER_ERROR_MESSAGE, error);
            exit(1);
        }
    };

    if total_parties <= threshold {
        println!("Not enough parties are joined: {}", total_parties);
        exit(1);
    }

    if  params.parties.parse::<u16>().unwrap() < output.number  {
        println!("Invalid ID assigned to party: {}", output.number);
        exit(1);
    }

    Ok((output, total_parties))
}

pub fn sha256_digest(input: &[u8]) -> String {
    let mut sha256 = Sha256::new();
    sha256.update(input);
    let hash: String = format!("{:X}", sha256.finalize());
    hash
}

pub(crate) fn generate_primes(limit: usize) -> Vec<usize> {
    use slow_primes;

    slow_primes::Primes::sieve(limit).primes().into_iter().collect()
}

pub(crate) fn is_divisible_by_first_n_primes(given_number: BigInt, limit_for_check: usize) -> bool {
    let mut failed = false;
    let primes = generate_primes(limit_for_check);
    for prime in primes.iter() {
        if (given_number.clone() % BigInt::from(*prime as u32)).is_zero() {
            println!("Failed! Divisible by {:?}", prime);
            failed = true; // The given number is divisible by one of the primes
        }
    }
    failed // The given number is not divisible by any of the primes
}

pub(crate) fn export_keys(input_dir: String) -> String {
    let (keyfiles, scheme) = detect_format_and_list_files(input_dir);
    match scheme {
        None => "Could not find any key files, or could not parse them".to_string(),
        Some(DKGSignScheme::ECDSA) => {
            println!("Detected ECDSA key files");
            match ecdsa::sum_of_fragment_files(keyfiles) {
                Ok((master_pubkey, file_master_pubkey, master_private_key)) => {
                    assert_eq!(master_pubkey.to_bytes(true).to_vec(),
                               file_master_pubkey.to_bytes(true).to_vec());
                    hex::encode(master_private_key.to_bytes().to_vec())
                }
                Err(error) => {
                    format!("Could not export key files. Error: {}", error)
                }
            }
        }
        Some(DKGSignScheme::EdDSA) => {
            println!("Detected EdDSA key files");
            match eddsa::sum_of_fragment_files(keyfiles) {
                Ok((master_pubkey, file_master_pubkey, master_private_key)) => {
                    assert_eq!(master_pubkey.to_bytes(true).to_vec(),
                               file_master_pubkey.to_bytes(true).to_vec());
                    hex::encode(master_private_key.to_bytes().to_vec())
                }
                Err(error) => {
                    format!("Could not export key files. Error: {}", error)
                }
            }
        }
    }
}

fn detect_format_and_list_files<P: AsRef<Path>>(dir: P) -> (Vec<String>, Option<DKGSignScheme>) {
    let mut files = Vec::new();
    let mut detected: Option<DKGSignScheme> = None;

    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.is_file() {
            files.push(path.to_string_lossy().to_string());
        }
    }

    if files.len() > 0 {
        let keyfile_path = files[0].to_string();
        if let Ok(_a) = ECDSAParameters::read_from_file(keyfile_path.clone()) {
            detected = Some(DKGSignScheme::ECDSA);
        } else if let Ok(_b) = EdDSAParameters::read_from_file(keyfile_path) {
            detected = Some(DKGSignScheme::EdDSA);
        }
    }

    (files, detected)
}
