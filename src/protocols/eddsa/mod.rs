use std::fs;
use std::process::exit;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Ed25519, Scalar, Point};
use multi_party_eddsa::protocols::thresholdsig::{Keys, SharedKeys};
use serde_json::{json, Value};
use crate::common::{validate_hex_string, validate_vss_scheme_vector, Params};
use crate::hd_keys;
use crate::protocols::{HdImplementation, CHAIN_CODE_ERROR_IN_FILE, INVALID_FRAGMENT_FILE_ERROR, INVALID_MASTER_PUBLIC_KEY_IN_FILE, INVALID_MESSAGE_STRING_ERROR, PARTY_ID_ERROR_IN_FILE, PARTY_INDEX_ERROR_IN_FILE, PRIVATE_KEY_ERROR_IN_FILE, PUBLIC_KEY_ERROR_IN_FILE, SHARED_KEY_ERROR_IN_FILE};

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
            return Err(PUBLIC_KEY_ERROR_IN_FILE.to_string());
        }

        if self.party_key.keypair.expanded_private_key.private_key.is_zero() {
            return Err(PRIVATE_KEY_ERROR_IN_FILE.to_string());
        }

        if self.party_key.keypair.expanded_private_key.prefix.is_zero() {
            return Err("Invalid prefix in party_key".to_string());
        }

        if self.party_key.party_index == 0 {
            return Err(PARTY_INDEX_ERROR_IN_FILE.to_string());
        }

        if self.chain_code.is_zero() {
            return Err(CHAIN_CODE_ERROR_IN_FILE.to_string());
        }

        if self.shared_keys.y.is_zero()
            || self.shared_keys.x_i.is_zero()
            || self.shared_keys.prefix.is_zero() {
            return Err(SHARED_KEY_ERROR_IN_FILE.to_string());
        }

        if self.party_id == 0 {
            return Err(PARTY_ID_ERROR_IN_FILE.to_string());
        }

        if self.master_public_key.is_zero() {
            return Err(INVALID_MASTER_PUBLIC_KEY_IN_FILE.to_string());
        }

        // Validate vss_scheme_vec: A vector of vectors of GE elements
        validate_vss_scheme_vector(self.vss_scheme_vec.clone())
    }
}

pub fn sign(
    manager_address:String,
    key_file_path: String,
    params: Vec<&str>,
    message_str:String,
    path: &str,
    hd_variant: HdImplementation
)-> Value {
    if !validate_hex_string(message_str.as_str()) {
        println!("{}", INVALID_MESSAGE_STRING_ERROR);
        exit(1);
    }

    let params = Params {
        threshold: params[0].to_string(),
        parties: params[1].to_string(),
    };

    let (signature, y_sum) = signer::run_signer(
        manager_address,
        key_file_path,
        params,
        message_str.clone(),
        path,
        hd_variant
    );

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


pub fn run_pubkey(keys_file_path:&str, path:&str, hd_variant: HdImplementation) -> Value {

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
            eprintln!("{}: {}", INVALID_FRAGMENT_FILE_ERROR, error);
            exit(1);
        },
    };

    // Get root pub key or HD pub key at specified path
    let (y_sum, _f_l_new, chain_code): (GE, FE, Vec<u8>) = match path.is_empty() {
        true => (y_sum, Scalar::<Ed25519>::zero(), chain_code.to_bytes().to_vec()),
        false => {
            match hd_variant {
                HdImplementation::Legacy => {
                    let chain_code = chain_code * GE::generator();
                    hd_keys::get_legacy_hd_key(&y_sum, path, chain_code)
                }
                HdImplementation::Bip32 => {
                    let chain_code_bytes = chain_code.to_bytes().to_vec();
                    let (derived_child, tweak, derived_chain_code)
                        = hd_keys::get_hd_key_by_crate(y_sum, path, chain_code_bytes);
                    let tweak_scaler = FE::from_bytes(tweak.as_slice()).unwrap();

                    (derived_child, tweak_scaler, derived_chain_code)
                }
            }
        }
    };

    // Return pub key as x,y
    let ret_dict = json!({
                "x": &y_sum.x_coord().unwrap().to_str_radix(16),
                "y": &y_sum.y_coord().unwrap().to_str_radix(16),
                "chain_code": hex::encode(chain_code),
                "path": path,
            });
    ret_dict
}


pub fn create_public_key_ed25519_bip32(pub_key: GE, chain_code: Vec<u8>) -> ed25519_bip32::XPub {
    let pub_bytes = pub_key.to_bytes(false).to_vec();
    let mut master_pub_key_bytes: [u8;32] = [0;32];
    master_pub_key_bytes.copy_from_slice(pub_bytes.as_slice());
    let mut master_chain_code_bytes: [u8;32] = [0;32];
    master_chain_code_bytes.copy_from_slice(chain_code.as_slice());

    ed25519_bip32::XPub::from_pk_and_chaincode(&master_pub_key_bytes, &master_chain_code_bytes)
}

pub(crate) fn sum_of_fragment_files(keyfiles: Vec<String>) -> Result<(GE, GE), String> {
    let mut sum_u_s = Scalar::<Ed25519>::zero();
    let mut master_y = Point::<Ed25519>::zero();
    for key_file_path in keyfiles.iter() {
        let EdDSAParameters {
            party_key: party_keys,
            chain_code: _,
            shared_keys: _,
            party_id: _,
            vss_scheme_vec: _,
            master_public_key: Y
        } = match EdDSAParameters::read_from_file(key_file_path.clone()) {
            Ok(x) => x,
            Err(error) => {
                eprintln!("{}: {}", INVALID_FRAGMENT_FILE_ERROR, error);
                return Err(error);
            }
        };
        sum_u_s = sum_u_s + party_keys.keypair.expanded_private_key.private_key;
        master_y = Y;
    }
    // sum_u_s is actually the master private key:
    let summation_pub_key = sum_u_s.clone() * Point::generator();
    Ok((summation_pub_key, master_y))
}