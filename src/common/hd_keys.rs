use std::convert::{TryFrom, TryInto};
use bip32::{
    ChildNumber,
    ExtendedKeyAttrs,
    KeyFingerprint,
    PublicKey,
    PublicKeyBytes,
    XPub,
    XPrv,
    ExtendedKey,
    Prefix
};
use bip32::secp256k1::ecdsa::VerifyingKey;
use curv::arithmetic::{Converter, BasicOps, One};
use curv::BigInt;
use curv::elliptic::curves::{Curve, Ed25519, Point, Scalar, Secp256k1};

use curv::cryptographic_primitives::hashing::HmacExt;
use ed25519_bip32::DerivationScheme;
use hmac::Hmac;
use sha2::{Sha512};
use crate::protocols::eddsa::{create_private_key_ed25519_bip32, create_public_key_ed25519_bip32};

pub fn get_legacy_hd_key<E: Curve>(y_sum: &Point<E>, path: &str, chain_code: Point<E>) -> (Point<E>, Scalar<E>, Vec<u8>) {
    let path_vector: Vec<BigInt> = path
        .split('/')
        .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
        .collect();

    // derive a new pubkey and LR sequence, y_sum becomes a new child pub key
    let (y_sum_child, f_l_new, cc_new) = legacy_hd_key(
        path_vector,
        &y_sum,
        &BigInt::from_bytes(&chain_code.to_bytes(true)),
    );
    let y_sum = y_sum_child.clone();
    //    println!("New public key: {:?}", &y_sum);
    //    println!("Public key X: {:?}", &y_sum.x_coor());
    //    println!("Public key Y: {:?}", &y_sum.y_coor());
    (y_sum, f_l_new, cc_new.to_bytes(true).to_vec())
}

pub fn legacy_hd_key<E: Curve>(
    mut location_in_hir: Vec<BigInt>,
    pubkey: &Point<E>,
    chain_code_bi: &BigInt,
) -> (Point<E>, Scalar<E>, Point<E>) {
    let mask = BigInt::from(2 as i32).pow(256) - BigInt::one();
    // let public_key = self.public.q.clone();

    // calc first element:
    let first = location_in_hir.remove(0);
    let pub_key_bi = BigInt::from_bytes(&pubkey.to_bytes(true));
    let f = Hmac::<Sha512>::new_bigint(chain_code_bi)
        .chain_bigint(&pub_key_bi)
        .chain_bigint(&first)
        .result_bigint();

    let f_l = &f >> 256;
    let f_r = &f & &mask;
    let f_l_fe: Scalar<E> = Scalar::<E>::from(&f_l);
    let f_r_fe: Scalar<E> = Scalar::<E>::from(&f_r);

    let bn_to_slice = BigInt::to_bytes(chain_code_bi);
    let chain_code = Point::<E>::from_bytes(&bn_to_slice.as_slice()).unwrap() * &f_r_fe;
    let g: Point<E> = Point::<E>::generator().to_point();
    let pub_key = pubkey.clone() + g.clone() * &f_l_fe;

    let (public_key_new_child, f_l_new, cc_new) =
        location_in_hir
            .iter()
            .fold((pub_key, f_l_fe, chain_code), |acc, index| {
                let pub_key_bi = BigInt::from_bytes(&acc.0.to_bytes(true));
                let f = Hmac::<Sha512>::new_bigint(&BigInt::from_bytes(&acc.2.to_bytes(true)))
                    .chain_bigint(&pub_key_bi)
                    .chain_bigint(index)
                    .result_bigint();

                let f_l = &f >> 256;
                let f_r = &f & &mask;
                let f_l_fe: Scalar<E> = Scalar::<E>::from(&f_l);
                let f_r_fe: Scalar<E> = Scalar::<E>::from(&f_r);

                (acc.0 + &g * &f_l_fe, f_l_fe + &acc.1, &acc.2 * &f_r_fe)
            });
    (public_key_new_child, f_l_new, cc_new)
}


pub trait HdCurveHandler {
    fn get_hd_child(y_sum: Point<Self>, path: &str, chain_code: Vec<u8>) -> (Point<Self>, Vec<u8>, Vec<u8>) where Self: Curve;
    fn get_hardened_hd_child(private_key: Scalar<Self>, path: &str, chain_code: Vec<u8>) -> (Point<Self>, Vec<u8>, Vec<u8>) where Self: Curve;
}

fn parse_hd_path(path: &str) -> Vec<(u32, bool)> {
    path.split('/')
        .map(|s| {
            let hardened = s.ends_with('\'');
            let number_str = if hardened { &s[..s.len() - 1] } else { s };
            let number = number_str.parse::<u32>().expect("Invalid number");
            (number, hardened)
        })
        .collect()
}

pub fn hd_path_to_integer(index: u32, is_hardened: bool) -> u32 {
    if is_hardened {
        index + 0x80000000
    } else {
        index
    }
}

impl HdCurveHandler for Secp256k1 {
    fn get_hd_child(pub_key: Point<Self>, path: &str, chain_code: Vec<u8>) -> (Point<Self>, Vec<u8>, Vec<u8>) {
        let master_pub_key_bytes = pub_key.to_bytes(true).to_vec();
        let master_chain_code_bytes = &chain_code[0..32];

        let finger_print = KeyFingerprint::from([0u8; 4]);
        let pub_key_bytes: PublicKeyBytes = master_pub_key_bytes.try_into().unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes).unwrap();

        let pub_key_crate = XPub::new(verifying_key, ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: finger_print,
            child_number: ChildNumber(10), //This is not important during HD derivation
            chain_code: master_chain_code_bytes.try_into().unwrap(),
        });

        let path_numbers: Vec<(u32, bool)> = parse_hd_path(path);

        let mut child_key = pub_key_crate;
        let mut tweak_scalar: Scalar<Self> = Scalar::<Self>::zero();
        for (child_path, _is_hardened) in path_numbers {
            let child_num = ChildNumber(child_path);
            let (child_tweak, _chain_code) = child_key
                .public_key()
                .derive_tweak(&child_key.attrs().chain_code, child_num).unwrap();
            tweak_scalar = tweak_scalar + Scalar::<Self>::from_bytes(child_tweak.as_slice()).unwrap();
            child_key = child_key.derive_child(child_num).unwrap();
        }
        let child_pub_key = Point::<Secp256k1>::from_bytes(&child_key.public_key().to_bytes()).unwrap();
        let child_chain_code= child_key.attrs().chain_code.to_vec();
        (child_pub_key, tweak_scalar.to_bytes().to_vec(), child_chain_code)
    }

    fn get_hardened_hd_child(private_key: Scalar<Self>, path: &str, chain_code: Vec<u8>) -> (Point<Self>, Vec<u8>, Vec<u8>) {
        let mut parent_private_key_bytes = private_key.to_bytes().to_vec();
        parent_private_key_bytes.insert(0, 0);
        let master_chain_code_bytes = &chain_code[0..32];

        let finger_print = KeyFingerprint::from([0u8; 4]);
        //let prv_key_bytes: PrivateKeyBytes = parent_private_key_bytes.try_into().unwrap();
        //let parent_private_key = PrivateKey::from_bytes(&prv_key_bytes).unwrap();
        let extended_key_crate = ExtendedKey {
            prefix: Prefix::XPRV,
            attrs: ExtendedKeyAttrs {
                depth: 0,
                parent_fingerprint: finger_print,
                child_number: ChildNumber(10), //This is not important during HD derivation
                chain_code: master_chain_code_bytes.try_into().unwrap(),
            },
            key_bytes: parent_private_key_bytes.try_into().unwrap(),
        };
        let pub_key_crate: XPrv = XPrv::try_from(extended_key_crate).unwrap();

        let path_numbers: Vec<(u32, bool)> = parse_hd_path(path);

        let mut child_key = pub_key_crate;
        for (child_path, is_hardened) in path_numbers {
            let child_num = ChildNumber::new(child_path, is_hardened).unwrap();
            child_key = child_key.derive_child(child_num).unwrap();
        }
        let child_chain_code= child_key.attrs().chain_code.to_vec();
        let child_private_key_bytes = child_key.private_key().to_bytes();
        //let child_private_key_scalar = Scalar::<Self>::from_bytes(&child_private_key_bytes).unwrap();
        //let tweak_bytes = (child_private_key_scalar - private_key).to_bytes();
        let tweak_bytes = child_private_key_bytes;
        let child_pub_key = Point::<Self>::from_bytes(&child_key.public_key().to_bytes()).unwrap();
        (child_pub_key, tweak_bytes.to_vec(), child_chain_code)
    }
}

impl HdCurveHandler for Ed25519 {
    fn get_hd_child(pub_key: Point<Self>, path: &str, chain_code: Vec<u8>) -> (Point<Self>, Vec<u8>, Vec<u8>) {
        let mut path_numbers = path
            .split('/')
            .map(|s| s.parse::<u32>().expect("Invalid number"))
            .collect::<Vec<u32>>();

        // Here, it is not a child yet, but parent. However, we name it child, to reuse it in loop:
        let parent = create_public_key_ed25519_bip32(pub_key.clone(), chain_code);
        /*
        For some scalars, adding to zero yields a different scalar! For example
            let seed = "b2ad625ca5ae78e6e36600ba82d674ac044fedf75698567dab20cbf836501010";
            let the_scalar = Scalar::<Ed25519>::from_bytes(&hex::decode(seed).unwrap()).unwrap();
            let final_scalar = the_scalar.clone() + Scalar::<Ed25519>::zero();
            assert_eq!(the_scalar, final_scalar); // This fails
         So, I handle the first element of path separately, and the rest inside the loop:
         */
        let first_index = path_numbers.remove(0);
        let derivation_result = parent.derive(DerivationScheme::V2, first_index).unwrap();
        let mut child_key = derivation_result.pub_key;
        let mut tweak_scalar: Scalar<Self> = Scalar::<Self>::from_bytes(&derivation_result.tweak).unwrap();
        for child_path in path_numbers {
            let derivation_result = child_key.derive(DerivationScheme::V2, child_path).unwrap();
            child_key = derivation_result.pub_key;
            let tweak = derivation_result.tweak;
            tweak_scalar = tweak_scalar + Scalar::<Self>::from_bytes(tweak.as_slice()).unwrap();
        }

        //let child_bytes = &child_key.public_key();
        //let child_scalar = Scalar::<Ed25519>::from_bytes(child_bytes).unwrap();
        let g: Point<Ed25519> = Point::<Ed25519>::generator().to_point();
        let child_pub_key = pub_key.clone() + g.clone() * &tweak_scalar;

        (child_pub_key, tweak_scalar.to_bytes().to_vec(), child_key.chain_code().to_vec())
    }

    fn get_hardened_hd_child(private_key: Scalar<Self>, path: &str, chain_code: Vec<u8>) -> (Point<Self>, Vec<u8>, Vec<u8>) {
        let path_numbers = parse_hd_path(path);

        // Here, it is not a child yet, but parent. However, we name it child, to reuse it in loop:
        let mut child_key = create_private_key_ed25519_bip32(private_key.clone(), chain_code);
        for (mut child_path, is_hardened) in path_numbers {
            child_path = hd_path_to_integer(child_path, is_hardened);
            child_key = child_key.derive(DerivationScheme::V2, child_path);
        }
        let child_public_key_bytes = &child_key.public().public_key();
        let child_pub_key = Point::<Ed25519>::from_bytes(child_public_key_bytes).unwrap();
        let child_private_key_bytes = &child_key.extended_secret_key()[0..32];
        (child_pub_key, child_private_key_bytes.to_vec(), child_key.chain_code().to_vec())
    }
}

pub fn get_hd_child_by_crate<E: HdCurveHandler + Curve>(y_sum: Point<E>, path: &str, chain_code: Vec<u8>) -> (Point<E>, Vec<u8>, Vec<u8>) {
    E::get_hd_child(y_sum, path, chain_code)
}

pub fn get_hardened_hd_child_by_crate<E: HdCurveHandler + Curve>(private_key: Scalar<E>, path: &str, chain_code: Vec<u8>) -> (Point<E>, Vec<u8>, Vec<u8>) {
    E::get_hardened_hd_child(private_key, path, chain_code)
}
