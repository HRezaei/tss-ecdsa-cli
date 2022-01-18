use std::fs;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Ed25519, Scalar};
use ed25519_bip32::{DerivationScheme, XPub};
use multi_party_eddsa::protocols::{FE, GE};
use multi_party_eddsa::protocols::thresholdsig::{Keys, SharedKeys};
use serde_json::{json, Value};
use crate::common::Params;
use crate::hd_keys;

pub mod keygen;
pub mod signer;
mod test;

pub static CURVE_NAME: &str = "EdDSA";


pub fn sign(manager_address:String, key_file_path: String, params: Vec<&str>, message_str:String, path: &str)
            -> Value {
    let params = Params {
        threshold: params[0].to_string(),
        parties: params[1].to_string(),
    };

    let (signature, y_sum) = signer::run_signer(manager_address, key_file_path, params, message_str.clone(), path);

    let ret_dict = json!({
        "r": (BigInt::from_bytes(&(signature.R.to_bytes(false)))).to_str_radix(16),
        "s": (BigInt::from_bytes(&(signature.s.to_bytes()))).to_str_radix(16),
        "status": "signature_ready",
        "x": &y_sum.x_coord(),
        "y": &y_sum.y_coord(),
        "msg_int": message_str.as_bytes().to_vec().as_slice(),
    });

    //fs::write("signature.json".to_string(), ret_dict.clone().to_string()).expect("Unable to save !");

    ret_dict
}


pub fn run_pubkey(keys_file_path:&str, path:&str) -> Value {

    // Read data from keys file
    let data = fs::read_to_string(keys_file_path).expect(
        format!("Unable to load keys file at location: {}", keys_file_path).as_str(),
    );
    let (_party_keys, _shared_keys, _party_id, _vss_scheme_vec, y_sum, chain_code): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Ed25519>>,
        GE,
        [u8;32]
    ) = serde_json::from_str(&data).unwrap();

    // Get root pub key or HD pub key at specified path
    let (y_sum, chain_code): (GE, [u8;32]) = match path.is_empty() {
        true => (y_sum, chain_code),
        false => {
            let (y_sum_child, chain_code_child) = derive_hd_key(y_sum, chain_code, path.to_string());
            (y_sum_child.clone(), chain_code_child)
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


pub fn derive_hd_key(public_key: GE, chain_code: [u8;32], path: String) -> (GE, [u8;32]) {
    let mut public_key_bytes = [0u8;64];
    public_key_bytes[0..32].copy_from_slice(public_key.to_bytes(true).as_ref());
    public_key_bytes[32..64].copy_from_slice(chain_code.as_ref());

    let pub_key_without_private = XPub::from_bytes(public_key_bytes);

    let path_vector: Vec<u32> = path
        .split('/')
        .map(|s| s.parse::<u32>().unwrap())
        .collect();
    let mut child = pub_key_without_private;
    for index in path_vector {
        child = child.derive(DerivationScheme::V2, index).unwrap();
    }

    let child_public_key = GE::from_bytes(child.public_key_slice()).unwrap();
    let child_chain_code = child.chain_code();
    (child_public_key, child_chain_code)
}