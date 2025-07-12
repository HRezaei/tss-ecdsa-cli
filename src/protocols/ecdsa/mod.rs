pub mod keygen;
pub mod signer;
pub mod curv7_conversion;

extern crate serde_json;
use serde_json::{json, Value};

use std::fs;
use std::process::exit;
use crate::common::{hd_keys, is_divisible_by_first_n_primes, validate_hex_string, validate_vss_scheme_vector, Params, MAX_FIRST_PRIMES};

//use aes_gcm::aead::{NewAead};

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use paillier::EncryptionKey;

use curv::{arithmetic::traits::Converter};
use curv::arithmetic::Zero;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, SharedKeys
};
use crate::protocols::{INVALID_FRAGMENT_FILE_ERROR, INVALID_MESSAGE_STRING_ERROR};

//pub type Key = String;
pub static CURVE_NAME: &str = "ECDSA";
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;

pub struct ECDSAParameters {
    party_key: Keys,
    chain_code: FE,
    shared_keys: SharedKeys,
    party_id: u16,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    pub(crate) paillier_key_vec: Vec<EncryptionKey>,
    master_public_key: GE,
}

impl ECDSAParameters {

    pub fn read_from_file(keys_file_path: String) -> Result<ECDSAParameters, String> {
        // Read data from keys file
        let data = fs::read_to_string(keys_file_path.clone()).expect(
            format!("Unable to load keys file at location: {}", keys_file_path).as_str(),
        );
        let (party_key, chain_code, shared_keys, party_id, vss_scheme_vec, paillier_key_vec, master_public_key): (
            Keys,
            Scalar<Secp256k1>,
            SharedKeys,
            u16,
            Vec<VerifiableSS<Secp256k1>>,
            Vec<EncryptionKey>,
            GE,
        ) = serde_json::from_str(&data).unwrap();

        let ecdsa_params = ECDSAParameters {
            party_key,
            chain_code,
            shared_keys,
            party_id,
            vss_scheme_vec,
            paillier_key_vec,
            master_public_key,
        };

        match ecdsa_params.validate() {
            Ok(_valid) => Ok(ecdsa_params),
            Err(e) => Err(e),
        }
    }

    pub fn validate(&self) -> Result<bool, String> {
        if self.party_key.y_i.is_zero() {
            return Err("Invalid public key in party_key".to_string());
        }

        if self.party_key.u_i.is_zero() {
            return Err("Invalid private key in party_key".to_string());
        }

        if self.party_key.dk.p.is_zero() || self.party_key.dk.q.is_zero() {
            return Err("Invalid decryption key in party_key".to_string());
        }

        if self.party_key.ek.n.is_zero() || self.party_key.ek.nn.is_zero() {
            return Err("Invalid encryption key in party_key".to_string());
        }

        if self.party_key.party_index == 0 {
            return Err("Invalid party index in party_key".to_string());
        }

        if self.chain_code.is_zero() {
            return Err("Invalid chain code".to_string());
        }

        if self.shared_keys.y.is_zero()
            || self.shared_keys.x_i.is_zero() {
            return Err("Invalid shared keys".to_string());
        }

        if self.party_id == 0 {
            return Err("Invalid party ID".to_string());
        }

        if self.master_public_key.is_zero() {
            return Err("Invalid master public key".to_string());
        }

        // Validate vss_scheme_vec: A vector of vectors of GE elements
        validate_vss_scheme_vector(self.vss_scheme_vec.clone())
    }
}


pub fn run_pubkey_or_sign(
    action:&str,
    keysfile_path:&str,
    path:&str,
    message_str:&str,
    manager_addr:String,
    params:Vec<&str>,
) -> Value
{
    // Read data from keys file
    let ECDSAParameters {
        party_key,
        chain_code,
        shared_keys,
        party_id,
        mut vss_scheme_vec,
        paillier_key_vec,
        master_public_key: y_sum
    } = match ECDSAParameters::read_from_file (keysfile_path.to_string()) {
        Ok(params) => {params}
        Err(error) => {
            eprintln!("{}: {}", INVALID_FRAGMENT_FILE_ERROR, error);
            exit(1);
        }
    };

    // Get root pub key or HD pub key at specified path
    let (f_l_new, y_sum) = match path.is_empty() {
        true => (Scalar::<Secp256k1>::zero(), y_sum),
        false => {
            let chain_code= GE::generator() * chain_code;
            let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&y_sum, path, chain_code);
            (f_l_new, y_sum_child.clone())
        }
    };

    // Return pub key as x,y
    let result = if action == "pubkey" {
        let ret_dict = json!({
                    "x": &y_sum.x_coord().unwrap().to_str_radix(16),
                    "y": &y_sum.y_coord().unwrap().to_str_radix(16),
                    "path": path,
                });
        ret_dict
    }
    else {

        if !validate_hex_string(message_str) {
            println!("{}", INVALID_MESSAGE_STRING_ERROR);
            exit(1);
        }

        // Parse message to sign
        let message = match hex::decode(message_str) {
            Ok(x) => x,
            Err(_e) => message_str.as_bytes().to_vec(),
        };
        let message = &message[..];

        //            println!("sign me {:?} / {:?} / {:?}", manager_addr, message, params);
        let params = Params {
            threshold: params[0].to_string(),
            parties: params[1].to_string(),
        };
        signer::sign(
            manager_addr,
            party_key,
            shared_keys,
            party_id,
            &mut vss_scheme_vec,
            paillier_key_vec,
            &y_sum,
            &params,
            &message,
            &f_l_new,
            !path.is_empty(),
        )
    };

    result
}

pub(crate) fn check_key_file(keysfile_path:&str, limit: usize) -> bool {
    // Read data from keys file
    match ECDSAParameters::read_from_file (keysfile_path.to_string()) {
        Ok(params) => {
            println!("MAX_FIRST_PRIMES is set to: {:?}", MAX_FIRST_PRIMES);


            let mut failed = false;
            println!("Checking paillier_key_vector[..].n");
            for paillier_key in params.paillier_key_vec.iter() {
                if is_divisible_by_first_n_primes(paillier_key.n.clone(), limit) {
                    failed = true;
                };
            }

            failed
        }
        Err(error) => {
            eprintln!("{}: {}", INVALID_FRAGMENT_FILE_ERROR, error);
            exit(1);
        }
    }
}
