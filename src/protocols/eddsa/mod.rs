use std::fs;
use std::process::exit;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Ed25519, Scalar, Point};
use multi_party_eddsa::protocols::thresholdsig::{Keys, SharedKeys};
use serde_json::{json, Value};
use crate::common::{validate_hex_string, validate_vss_scheme_vector, Params};
use crate::eddsa::signer::update_hd_derived_public_key;
use crate::hd_keys;

pub mod keygen;
pub mod signer;
mod test;

pub type FE = Scalar<Ed25519>;
pub type GE = Point<Ed25519>;

pub static CURVE_NAME: &str = "EdDSA";

pub struct EdDSAParameters {
    party_key: Keys,
    chain_code: Scalar<Ed25519>,
    shared_keys: SharedKeys,
    party_id: u16,
    vss_scheme_vec: Vec<VerifiableSS<Ed25519>>,
    master_public_key: GE,
}

impl EdDSAParameters {

    pub fn read_from_file(keys_file_path: String) -> Result<EdDSAParameters, String> {
        // Read data from keys file
        let data = fs::read_to_string(keys_file_path.clone()).expect(
            format!("Unable to load keys file at location: {}", keys_file_path).as_str(),
        );
        let (party_key, chain_code, shared_keys, party_id, vss_scheme_vec, master_public_key): (
            Keys,
            Scalar<Ed25519>,
            SharedKeys,
            u16,
            Vec<VerifiableSS<Ed25519>>,
            GE,
        ) = serde_json::from_str(&data).unwrap();

        let eddsa_params = EdDSAParameters{
            party_key,
            chain_code,
            shared_keys,
            party_id,
            vss_scheme_vec,
            master_public_key,
        };

        match eddsa_params.validate() {
            Ok(_valid) => Ok(eddsa_params),
            Err(e) => Err(e),
        }
    }

    pub fn validate(&self) -> Result<bool, String> {
        if self.party_key.keypair.public_key.is_zero() {
            return Err("Invalid public key in party_key".to_string());
        }

        if self.party_key.keypair.expanded_private_key.private_key.is_zero() {
            return Err("Invalid private key in party_key".to_string());
        }

        if self.party_key.keypair.expanded_private_key.prefix.is_zero() {
            return Err("Invalid prefix in party_key".to_string());
        }

        if self.party_key.party_index == 0 {
            return Err("Invalid party index in party_key".to_string());
        }

        if self.chain_code.is_zero() {
            return Err("Invalid chain code".to_string());
        }

        if self.shared_keys.y.is_zero()
            || self.shared_keys.x_i.is_zero()
            || self.shared_keys.prefix.is_zero() {
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

pub fn sign(manager_address:String, key_file_path: String, params: Vec<&str>, message_str:String, path: &str)
            -> Value {
    if !validate_hex_string(message_str.as_str()) {
        println!("Invalid message string.");
        exit(1);
    }

    let params = Params {
        threshold: params[0].to_string(),
        parties: params[1].to_string(),
    };

    let (signature, y_sum) = signer::run_signer(manager_address, key_file_path, params, message_str.clone(), path);

    let ret_dict = json!({
        "r": (BigInt::from_bytes(&(signature.R.to_bytes(false)))).to_str_radix(16),
        "s": (BigInt::from_bytes(&(signature.s.to_bytes()))).to_str_radix(16),
        "status": "signature_ready",
        "x": &y_sum.x_coord().unwrap().to_str_radix(16),
        "y": &y_sum.y_coord().unwrap().to_str_radix(16),
        "msg_int": message_str.as_bytes().to_vec().as_slice(),
    });

    //fs::write("signature.json".to_string(), ret_dict.clone().to_string()).expect("Unable to save !");

    ret_dict
}


pub fn run_pubkey(keys_file_path:&str, path:&str) -> Value {

    // Read data from keys file
    let EdDSAParameters {
        party_key :_party_keys,
        chain_code,
        shared_keys: _shared_keys,
        party_id: _party_id,
        vss_scheme_vec: _vss_scheme_vec,
        master_public_key: y_sum
    } = match EdDSAParameters::read_from_file(keys_file_path.to_string()){
        Ok(params) => params,
        Err(error) => {
            eprintln!("Error loading file: {}", error);
            exit(1);
        },
    };

    // Get root pub key or HD pub key at specified path
    let (_f_l_new, y_sum): (FE, GE) = match path.is_empty() {
        true => (Scalar::<Ed25519>::zero(), y_sum),
        false => {
            let chain_code= chain_code * GE::generator();
            let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&y_sum, path, chain_code);

            let safe_public_key_child = update_hd_derived_public_key(y_sum_child);

            (f_l_new, safe_public_key_child)
        }
    };

    // Return pub key as x,y
    let ret_dict = json!({
                "x": &y_sum.x_coord().unwrap().to_str_radix(16),
                "y": &y_sum.y_coord().unwrap().to_str_radix(16),
                "path": path,
            });
    ret_dict
}
