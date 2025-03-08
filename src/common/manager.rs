use std::collections::HashMap;
use std::env;
use std::sync::RwLock;
use std::time::Duration;
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation, decode_header};
use rocket::{Ignite, post, Rocket, routes, State, async_trait, Request};
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::FromRequest;
use rocket::serde::json::Json;
use serde_json::json;
use jsonwebtoken::errors::{ErrorKind, Result as JwtResult};

use ttlhashmap::TtlHashMap;

use uuid::Uuid;

use crate::common::{error_message, Claims, Entry, Index, Key, ManagerError, Params, PartySignup, PartySignupRequestBody, SigningPartySignup};
use crate::common::signing_room::SigningRoom;

const HTTP_AUTH_KEY_PAIRS_VAR: &str = "TSS_MANAGER_HTTP_AUTH_KEY_PAIRS";
// Define the ApiKey struct, which will be extracted from the JWT token
pub struct ApiKeyJwt();

// Implementing FromRequest for ApiKey to validate JWT
#[async_trait]
impl<'r> FromRequest<'r> for ApiKeyJwt {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        let user_secret_keys = request.rocket().state::<HashMap<String, String>>()
            .expect("User secret keys not found");

        // Get the Authorization header
        if let Some(auth_header) = request.headers().get_one("Authorization") {
            // The Authorization header will be of the form "Bearer <token>"
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                match validate_jwt(token, user_secret_keys) {
                    Ok(_token_data) => {
                        // If JWT is valid, return the ApiKey
                        Outcome::Success(ApiKeyJwt())
                    }
                    Err(_) => {
                        // If JWT is invalid, return Unauthorized
                        Outcome::Error((Status::Unauthorized, "Invalid or expired token".to_string()))
                    }
                }
            } else {
                Outcome::Error((Status::Unauthorized, "Authorization header must start with Bearer".to_string()))
            }
        } else {
            Outcome::Error((Status::Unauthorized, "Authorization header missing".to_string()))
        }
    }
}


// Function to validate the JWT
fn validate_jwt(token: &str, user_secrets: &HashMap<String, String>) -> JwtResult<TokenData<Claims>> { //JwtResult<Claims>
    // Step 1: Decode the JWT to extract the claims
    let decoded_token = decode_header(token);

    match decoded_token {
        Ok(token_data) => {
            // Step 2: Get the API key from the decoded claims (kid)
            let api_key = token_data.kid.unwrap();

            // Step 3: Look up the secret key for that user (given api_key)
            if let Some(user_secret) = user_secrets.get(&api_key) {
                // Step 4: Validate the JWT using the user's secret key
                let decoding_key = DecodingKey::from_secret(user_secret.as_bytes());
                let validation = Validation::new(Algorithm::HS256);
                decode::<Claims>(token, &decoding_key, &validation)
            } else {
                Err(jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken))
            }
        }
        Err(err) => {
            Err(err)
        }
    }
}

fn parse_user_secrets_from_env() -> HashMap<String, String> {
    let mut user_secret_keys = HashMap::new();
    // Read the environment variable
    if let Ok(secret_string) = env::var(HTTP_AUTH_KEY_PAIRS_VAR) {
        // Parse the secret string, assuming a format like "user123=secretkey123,user456=secretkey456"
        for pair in secret_string.split(',') {
            let mut parts = pair.splitn(2, '=');
            if let (Some(api_key), Some(secret)) = (parts.next(), parts.next()) {
                user_secret_keys.insert(api_key.to_string(), secret.to_string());
            }
        }
    } else {
        eprintln!("{} environment variable is not set.", HTTP_AUTH_KEY_PAIRS_VAR);
    }

    user_secret_keys
}

#[rocket::main]
pub async fn run_manager() -> Result<Rocket<Ignite>, rocket::Error> {
    //     let mut my_config = Config::development();
    //     my_config.set_port(18001);
    let ttl = std::env::var("TSS_CLI_MANAGER_TTL")
        .unwrap_or("300".to_string()).parse::<u64>().unwrap();
    let db: TtlHashMap<Key, String> = TtlHashMap::new(Duration::from_secs(ttl));
    let db_mtx = RwLock::new(db);

    let user_secret_keys: HashMap<String, String> = parse_user_secrets_from_env();

    rocket::build()
        .mount("/", routes![get, set, signup_keygen, signup_sign])
        .manage(db_mtx)
        .manage(user_secret_keys)
        .launch()
        .await
}

#[post("/get", format = "json", data = "<request>")]
fn get(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<Index>,
    _jwt_guard: ApiKeyJwt
) -> Json<Result<Entry, ManagerError>> {
    let index: Index = request.0;
    let mut hm = db_mtx.write().unwrap();
    match hm.get(&index.key) {
        Some(v) => {
            let entry = Entry {
                key: index.key,
                value: v.clone().to_string(),
            };
            Json(Ok(entry))
        }
        None => {
            Json(Err(ManagerError{
                error: error_message("Invalid request",
                                     format!("Key not found: {}", index.key.as_str()).as_str()
                )
            }))
        },
    }
}

#[post("/set", format = "json", data = "<request>")]
fn set(db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
       request: Json<Entry>,
       _jwt_guard: ApiKeyJwt
) -> Json<Result<(), ()>> {
    let entry: Entry = request.0;
    let mut hm = db_mtx.write().unwrap();
    hm.insert(entry.key.clone(), entry.value.clone());
    Json(Ok(()))
}

#[post("/signupkeygen", format = "json", data = "<request>")]
fn signup_keygen(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<(Params, String)>,
    _jwt_guard: ApiKeyJwt
) -> Json<Result<PartySignup, ()>> {
    let parties = request.0.0.parties.parse::<u16>().unwrap();
    let curve = &request.0.1.parse::<String>().unwrap();
    let key = "signup-keygen-".to_string() + curve;
    let mut hm = db_mtx.write().unwrap();

    let client_signup = match hm.get(&key) {
        Some(o) => serde_json::from_str(o).unwrap(),
        None => PartySignup {
            number: 0,
            uuid: Uuid::new_v4().to_string(),
        },
    };

    let party_signup = {
        if client_signup.number < parties {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[post("/signupsign", format = "json", data = "<request>")]
fn signup_sign(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<PartySignupRequestBody>,
    _jwt_guard: ApiKeyJwt
) -> Json<Result<SigningPartySignup, ManagerError>> {
    let threshold = request.clone().threshold;
    let room_id = request.room_id.clone();
    let party_uuid = request.party_uuid.clone();
    let new_signup_request = party_uuid.is_empty();
    let party_number = request.party_number;
    let mut key = "signup-sign-".to_owned() + &request.curve_name;
    key.push_str(&room_id);

    let mut hm = db_mtx.write().unwrap();

    let mut signing_room = match hm.get(&key) {
        Some(o) => serde_json::from_str(o).unwrap(),
        None => SigningRoom::new(room_id.clone(), threshold+1),
    };

    if signing_room.last_stage != "signup" {
        if signing_room.has_member(party_number, party_uuid.clone()) {
            return Json(signing_room.get_signup_info(party_number));
        }

        if signing_room.are_all_members_inactive() {
            let debug = json!({
                "message": "All parties have been inactive. Renewed the room.",
                "room_id": room_id,
                "fragment.index": party_number,
            });
            println!("{}", serde_json::to_string_pretty(&debug).unwrap());
            signing_room = SigningRoom::new(room_id, threshold + 1)
        }
        else {
            return Json(Err(ManagerError{
                error: "Room signup phase is terminated".to_string()
            }));
        }
    }

    if signing_room.is_full() && signing_room.are_all_members_active() && new_signup_request {
        return Json(Err(ManagerError{
            error: "Room is full, all members active".to_string()
        }));
    }

    let party_signup_result = {
        if !new_signup_request {
            if !signing_room.has_member(party_number, party_uuid) {
                return Json(Err(ManagerError{
                    error: "No party found with the given uuid, probably replaced due to timeout".to_string()
                }));
            }
            //if signing_room.is_member_active(party_number) {
            signing_room.update_ping(party_number)
            //}
            //Else is handled in the next block
        } else if signing_room.member_info.contains_key(&party_number) {
            match signing_room.is_member_active(party_number) {
                Ok(is_active) => {
                    if is_active {
                        return Json(Err(ManagerError{
                            error: "Received a re-signup request for an active party. Request ignored".to_string()
                        }));
                    }
                    println!("Received a re-signup request for a timed-out party {:?}, thus UUID is renewed", party_number);
                    signing_room.replace_party(party_number)
                }
                Err(error) => {Err(error)}
            }
        }
        else {
            Ok(signing_room.add_party(party_number))
        }
    };

    match party_signup_result {
        Ok(party_signup) => {
            hm.insert(key.clone(), serde_json::to_string(&signing_room).unwrap());
            Json(Ok(party_signup))
        },
        Err(error) => Json(Err(error))
    }

}
