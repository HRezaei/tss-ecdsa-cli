pub mod keygen;
pub mod signer;
pub mod curv7_conversion;

extern crate serde_json;
use serde_json::{json, Value};

use std::fs;
use std::process::exit;
use crate::common::{hd_keys, validate_hex_string, Params};

//use aes_gcm::aead::{NewAead};

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use paillier::EncryptionKey;

use curv::{arithmetic::traits::Converter};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, SharedKeys
};


//pub type Key = String;
pub static CURVE_NAME: &str = "ECDSA";
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;


pub fn run_pubkey_or_sign(
    action:&str,
    keysfile_path:&str,
    path:&str,
    message_str:&str,
    manager_addr:String,
    params:Vec<&str>,
) -> Value
{
    if !validate_hex_string(message_str) {
        println!("Invalid message string.");
        exit(1);
    }
    // Read data from keys file
    let data = fs::read_to_string(keysfile_path).expect(
        format!("Unable to load keys file at location: {}", keysfile_path).as_str(),
    );
    let (party_keys, chain_code, shared_keys, party_id, mut vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        Scalar<Secp256k1>,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Secp256k1>>,
        Vec<EncryptionKey>,
        GE,
    ) = serde_json::from_str(&data).unwrap();

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
            party_keys,
            shared_keys,
            party_id,
            &mut vss_scheme_vec,
            paillier_key_vector,
            &y_sum,
            &params,
            &message,
            &f_l_new,
            !path.is_empty(),
        )
    };

    result
}
