use std::fs;
use curv::arithmetic::Converter;
use curv::BigInt;

use serde::{Deserialize, Serialize};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS};
use paillier::{DecryptionKey, EncryptionKey};
use curv::elliptic::curves::{Scalar, Secp256k1};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{Keys, SharedKeys};
use crate::ecdsa::{FE, GE};


type OldFE = String;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct OldGE {
    x: String,
    y: String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OldKeys {
    pub u_i: OldFE,
    pub y_i: OldGE,
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub party_index: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OldSharedKeys {
    pub y: OldGE,
    pub x_i: OldFE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct OldVerifiableSS {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<OldGE>,
}

fn convert_old_GE(old: &OldGE) -> GE {
    let old_x = BigInt::from_hex(&old.x).unwrap();
    let old_y = &BigInt::from_hex(&old.y).unwrap();

    GE::from_coords(&old_x, &old_y).unwrap()
}

fn convert_old_FE(mut old: OldFE) -> FE {
    if old.len() % 2 != 0 {
        old.insert(0,'0');
    }
    let old_bytes = hex::decode(old).unwrap();

    FE::from_bytes(old_bytes.as_slice()).unwrap()
}

fn convert_old_vss(vss: &OldVerifiableSS) -> VerifiableSS<Secp256k1> {

    let commitments = vss.commitments
        .iter()
        .map(|x| convert_old_GE(x))
        .collect();

    VerifiableSS{
        parameters: vss.clone().parameters,
        commitments
    }
}

pub fn convert_store_file(keys_file_path: String, destination_path: String)
    -> Result<String, String> {

    // Read data from keys file
    let data = fs::read_to_string(keys_file_path.clone()).expect(
        format!("Unable to load keys file at location: {}", keys_file_path).as_str(),
    );

    let (old_party_keys, old_shared_keys, party_id, old_vss_scheme_vec, paillier_key_vector, old_y_sum): (
        OldKeys,
        OldSharedKeys,
        u16,
        Vec<OldVerifiableSS>,
        Vec<EncryptionKey>,
        OldGE,
    ) = serde_json::from_str(&data).unwrap();

    
    let party_keys: Keys = Keys {
        u_i: convert_old_FE(old_party_keys.u_i),
        y_i: convert_old_GE(&old_party_keys.y_i),
        dk: old_party_keys.dk,
        ek: old_party_keys.ek,
        party_index: old_party_keys.party_index
    };
    
    let shared_keys = SharedKeys {
        y: convert_old_GE(&old_shared_keys.y),
        x_i: convert_old_FE(old_shared_keys.x_i)
    };

    let public_key = convert_old_GE(&old_y_sum);
    let vss_scheme_vector:Vec<VerifiableSS<Secp256k1>>  = old_vss_scheme_vec
        .iter()
        .map(|x| convert_old_vss(x))
        .collect();

    //In previous versions, GE::generator() has been used as chain code. Thus, in order
    //to keep backward compatibility, we set chain_code=1 so when multiplied by GE::generator()
    //produces the same chain code as before.
    //Please note that from this version onwards, we store chain code as a scalar, and upon use,
    //multiply it by generator to create a point as before.
    let fixed_chain_code = Scalar::<Secp256k1>::from(1 as u16);

    let keygen_json = serde_json::to_string(&(
        party_keys,
        fixed_chain_code,
        shared_keys,
        party_id,
        vss_scheme_vector,
        paillier_key_vector,
        public_key,
    ))
        .unwrap();

    fs::create_dir_all(std::path::Path::new(&destination_path).parent().unwrap())
        .map_err(|err| err.to_string())?;
    fs::write(&destination_path, keygen_json)
        .map_err(|e| format!("Unable to save in {}! Error: {:?}", destination_path, e))?;

    Ok(format!("Keys data written to file: {:?}", destination_path))
}