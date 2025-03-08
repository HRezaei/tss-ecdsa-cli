pub mod manager;
pub mod hd_keys;

pub mod signing_room;

use std::{env, fs, thread, time};
use std::time::{Instant, SystemTime, Duration};

use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use curv::arithmetic::{Zero};
use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{Keys, SharedKeys};
use paillier::EncryptionKey;
use std::process::exit;

use jsonwebtoken::{encode, EncodingKey, Header};
use reqwest::blocking::Client as RequestClient;
use serde::{Deserialize, Serialize};
use rand::{rngs::OsRng, TryRngCore};
use reqwest::header::{HeaderMap, AUTHORIZATION};
use sha2::{Sha256, Digest};


pub type Key = String;

pub(crate) const MAX_FIRST_PRIMES: usize =  2_i64.pow(25) as usize;

#[derive(Clone)]
pub struct Client {
    client: RequestClient,
    address: String
}

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;
pub const PARTY_HTTP_AUTH_APIKEY_VAR: &str = "TSS_PARTY_HTTP_AUTH_APIKEY";
pub const HTTP_AUTH_JWT_EXPIRY_VAR: &str = "TSS_HTTP_AUTH_JWT_TTL";
pub const HTTP_AUTH_JWT_EXPIRY_DEFAULT: &str = "10";
const HTTP_AUTH_JWT_SECRET_VAR: &str = "TSS_HTTP_AUTH_JWT_SECRET";
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
    pub fn new(addr: String) -> Self {
        Self {
            client: RequestClient::new(),
            address: addr
        }
    }
}

// Define the claims structure expected in the JWT
#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    api_key: String,
    exp: u64,
}

pub fn validate_hex_string(message: &str) -> bool {
    !message.is_empty() && message.chars().all(|c| c.is_ascii_hexdigit())
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let aes_key = aes_gcm::Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    let _ = OsRng.try_fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");

    AEAD {
        ciphertext: ciphertext,
        tag: nonce.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let aes_key = aes_gcm::Key::from_slice(key);
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    let out = gcm.decrypt(nonce, aead_pack.ciphertext.as_slice());
    out.unwrap()
}

fn generate_jwt() -> String {
    let http_api_key = env::var(PARTY_HTTP_AUTH_APIKEY_VAR).unwrap_or_else(|_|{
        eprintln!("Missing env variable: {}", PARTY_HTTP_AUTH_APIKEY_VAR);
        exit(1);
    });
    let jwt_expiry_seconds = env::var(HTTP_AUTH_JWT_EXPIRY_VAR)
        .unwrap_or(HTTP_AUTH_JWT_EXPIRY_DEFAULT.to_string()).parse::<u64>().unwrap_or_else(|e| {
        println!("Invalid value: {}", e);
        exit(1);
    });
    let secret_key = env::var(HTTP_AUTH_JWT_SECRET_VAR).unwrap_or_else(|_|{
        println!("Missing env variable: {}", HTTP_AUTH_JWT_SECRET_VAR);
        exit(1);
    });
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    // Prepare the JWT
    let claims = Claims {
        api_key: http_api_key.clone(), // The subject (party identifier)
        exp: now + jwt_expiry_seconds,
    };

    let mut header = Header::default();
    header.kid = Some(http_api_key);
    let encoding_key = EncodingKey::from_secret(secret_key.as_bytes());

    // Encode the JWT and return the token
    encode(&header, &claims, &encoding_key).unwrap()
}

pub fn postb<T>(client: &Client, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
{
    let addr = client.address.clone();
    let retries = 3;
    let retry_delay = time::Duration::from_millis(250);
    let jwt_token = generate_jwt();

    // Create the headers with the API key
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, format!("Bearer {}", jwt_token).parse().unwrap());

    for _i in 1..retries {
        let addr = format!("{}/{}", addr, path);
        let res = client.client.post(&addr)
            .headers(headers.clone())
            .json(&body)
            .send();

        if let Ok(res) = res {
            return Some(res.text().unwrap());
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
    let timeout = std::env::var("TSS_CLI_POLL_TIMEOUT")
        .unwrap_or("30".to_string()).parse::<u64>().unwrap();
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
                    panic!("Polling timed out! No response received from party number {:?}", i);
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
    let timeout = std::env::var("TSS_CLI_POLL_TIMEOUT")
        .unwrap_or("30".to_string()).parse::<u64>().unwrap();
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

pub fn keygen_signup(client: &Client, params: &Params, curve_name: &str) -> Result<PartySignup, ()> {
    let res_body = postb(&client, "signupkeygen", (params, curve_name)).unwrap();
    serde_json::from_str(&res_body).unwrap()
}

/*pub fn signup(path:&str, client: &Client, params: &Params, curve_name: &str) -> Result<PartySignup, ()> {
    let res_body = postb(&client, path, (params, curve_name)).unwrap();
    serde_json::from_str(&res_body).unwrap()
}*/

pub fn signup(path: &str, client: &Client, params: &Params, room_id: String, party_id: u16, curve_name: &str) -> Result<(PartySignup, u16), ()> {
    let mut request_body = PartySignupRequestBody{
        threshold: params.threshold.parse::<u16>().unwrap(),
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
                        panic!("{}", error);
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
            panic!("{}", error);
        }
    };

    return Ok((output, total_parties));
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

pub(crate) fn check_key_file(keysfile_path:&str, limit: usize) -> bool {
    // Read data from keys file
    let data = fs::read_to_string(keysfile_path).expect(
        format!("Unable to load keys file at location: {}", keysfile_path).as_str(),
    );

    let (_party_keys, _chain_code, _shared_keys, _party_id, _vss_scheme_vec, paillier_key_vector, _y_sum): (
        Keys,
        Scalar<Secp256k1>,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Secp256k1>>,
        Vec<EncryptionKey>,
        Point<Secp256k1>,
    ) = serde_json::from_str(&data).unwrap();

    println!("MAX_FIRST_PRIMES is set to: {:?}", MAX_FIRST_PRIMES);


    let mut failed = false;
    println!("Checking paillier_key_vector[..].n");
    for paillier_key in paillier_key_vector.iter() {
        if is_divisible_by_first_n_primes(paillier_key.n.clone(), limit) {
                failed = true;
        };
    }

    failed
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