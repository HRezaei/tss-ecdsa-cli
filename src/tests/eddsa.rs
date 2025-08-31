
use curv::arithmetic::Converter;
use curv::BigInt;
use ed25519_bip32::{DerivationScheme, Signature, XPrv};
use ed25519_bip32::{XPub};

use curv::elliptic::curves::{Ed25519, Point, Scalar};
use crate::common::hd_keys;
use crate::common::hd_keys::{get_legacy_hd_key};
use multi_party_eddsa::protocols::Signature as ZengoSignature;
use crate::protocols::eddsa::{create_public_key_ed25519_bip32};

type GE = Point<Ed25519>;
type FE = Scalar<Ed25519>;

fn pub_key_split(pub_key: XPub) -> (String, String) {
    let uncompressed = pub_key.public_key_slice();

    let pub_key_bytes = &uncompressed[0..32]; // bytes 0 to 32
    let chain_code = &pub_key.chain_code()[0..32]; // bytes 0 to 32

    (hex::encode(pub_key_bytes), hex::encode(chain_code))
}

fn derive_child_by_crate_ed25519_bip32(
    pub_key: [u8; 32],
    chain_code: [u8; 32],
    path: String,
) -> (String, String) {
    let pub_key_crate = XPub::from_pk_and_chaincode(&pub_key, &chain_code);

    let path_numbers = path
        .split('/')
        .map(|s| s.parse::<u32>().expect("Invalid number"));

    let mut child_key = pub_key_crate;
    for child_path in path_numbers {
        let derivation_result = child_key.derive(DerivationScheme::V2, child_path).unwrap();
        child_key = derivation_result.pub_key
    }

    let (child_x, child_chain_code) = pub_key_split(child_key);

    (child_x, child_chain_code)
}

fn derive_child_by_crate_ed25519_bip32_core(
    pub_key: [u8; 32],
    chain_code: [u8; 32],
    path: String,
) -> (String, String) {
    use ed25519_bip32_core::{
        DerivationIndex, DerivationScheme as SchemeCore, XPub as XPubCore,
    };

    let master_core = XPubCore::from_pk_and_chaincode(&pub_key, &chain_code);
    let path_numbers = path
        .split('/')
        .map(|s| s.parse::<u32>().expect("Invalid number"));

    let mut child_key = master_core;
    for child_path in path_numbers {
        let derivation_index = DerivationIndex::from(child_path);
        child_key = child_key
            .derive(SchemeCore::V2, derivation_index)
            .expect("core derivation fail");
    }

    let uncompressed = child_key.public_key_slice();

    let x = &uncompressed[0..32]; // bytes 0 to 32
    let chain_code = &child_key.chain_code()[0..32]; // bytes 0 to 32

    (hex::encode(x), hex::encode(chain_code))
}

#[test]
fn test_data_type_conversions() {
    let raw_bytes = [
        41, 9, 42, 231, 181, 54, 70, 117, 106, 129, 35, 18, 215, 174, 142, 187, 186, 189, 125,
        129, 103, 131, 219, 52, 59, 89, 213, 14, 180, 27, 125, 250,
    ];

    let my_big_int = BigInt::from_bytes(raw_bytes.as_ref());
    let big_int_bytes = my_big_int.to_bytes();

    assert_eq!(big_int_bytes, raw_bytes);

    let pub_key = Point::<Ed25519>::from_bytes(raw_bytes.as_slice()).unwrap();
    let pub_key_bytes = pub_key.to_bytes(true).to_vec();
    assert_eq!(pub_key_bytes, raw_bytes);

    //These two tests fail, and I don't think they should pass:
    /*let x_bytes = pub_key.x_coord().unwrap().to_bytes();
    let y_bytes = pub_key.y_coord().unwrap().to_bytes();
    assert_eq!(x_bytes.len(), raw_bytes.len());
    assert_eq!(y_bytes, raw_bytes);
    assert_eq!(x_bytes, raw_bytes);
     */
}

#[test]
fn test_signing_by_different_crates() {
    let master_private_key_bytes = [
        41, 9, 42, 231, 181, 54, 70, 117, 106, 129, 35, 18, 215, 174, 142, 187, 186, 189, 125,
        129, 103, 131, 219, 52, 59, 89, 213, 14, 180, 27, 125, 250,
    ];
    let master_chain_code_bytes = [
        245, 182, 135, 71, 224, 139, 206, 15, 200, 27, 106, 253, 197, 91, 155, 228, 38, 58,
        116, 150, 154, 116, 219, 141, 107, 189, 158, 80, 10, 82, 202, 13,
    ];
    let private_key = XPrv::from_nonextended_force(&master_private_key_bytes, &master_chain_code_bytes);
    let message = "test message".as_bytes();
    let bip32_signature: Signature<Vec<u8>> = private_key.sign(message);
    assert!(private_key.verify(message, &bip32_signature));

    let master_public_key = private_key.public();
    assert!(master_public_key.verify(message, &bip32_signature));

    //println!("{:?}", master_public_key.public_key());
    //prints: [37, 184, 15, 82, 56, 215, 159, 240, 12, 129, 87, 130, 55, 130, 64, 3, 213, 76, 184, 199, 37, 127, 244, 35, 180, 97, 89, 56, 27, 182, 134, 168]
    //println!("{:?}", master_public_key.chain_code());
    //prints: [245, 182, 135, 71, 224, 139, 206, 15, 200, 27, 106, 253, 197, 91, 155, 228, 38, 58, 116, 150, 154, 116, 219, 141, 107, 189, 158, 80, 10, 82, 202, 13]

    //Now let's recreate the public key, assuming we don't have access to private key:
    let master_pub_key_bytes = [37, 184, 15, 82, 56, 215, 159, 240, 12, 129, 87, 130,
        55, 130, 64, 3, 213, 76, 184, 199, 37, 127, 244, 35, 180, 97, 89, 56, 27, 182, 134, 168];

    let recreated_master_public_key = XPub::from_pk_and_chaincode(&master_pub_key_bytes, &master_chain_code_bytes);
    assert!(recreated_master_public_key.verify(message, &bip32_signature));

    //Now, let's create a public key of the type used tss-cli using the
    // same data used in recreation, and try to verify the same signature:
    let master_public_key: Point<Ed25519> = Point::<Ed25519>::from_bytes(&master_pub_key_bytes).unwrap();
    let chain_code_scalar = FE::from_bytes(&master_chain_code_bytes).unwrap();

    let zengo_signature: ZengoSignature = ZengoSignature {
        R: Point::from_bytes(&bip32_signature.as_ref()[..32]).unwrap(),
        s: Scalar::from_bytes(&bip32_signature.as_ref()[32..]).unwrap(),
    };
    assert!(zengo_signature.verify(message, &master_public_key).is_ok());

    //Lastly, let's create a pub key out of point on the curve and verify signature:
    let cc_byes = chain_code_scalar.to_bytes().to_vec();
    let pub_key_crate = create_public_key_ed25519_bip32(master_public_key, cc_byes);
    assert!(pub_key_crate.verify(message, &bip32_signature));
}

#[test]
fn test_pub_key_conversions() {
    let signature_r_hex = "d09f802383c194bd8cab3c307bdbe4f3bef06bd9ea947a63f82b3087848d78b3";
    let signature_s_hex = "c329d48f4aee6b7003fe3c8dc3e679d409319ae8bb12c07d3c43df588d9e910a";
    let message_hex = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4";
    let pub_key_x_hex = "4cbd68413501e54b86fe5e979266e2f26200e0d4913fb311332b8af6059767c2";
    let pub_key_y_hex = "ca38ae292957383c4e7ebe7be3e7f7cbe5caa565d3ed3e4791d745e6c2ace6d1";
    let chain_code_hex = "356a30825dc73b104e4fa65d3e39304705a9f0c1329862bf545cd0bd61cf9908";

    let signature_r_bytes = hex::decode(signature_r_hex).unwrap();
    let signature_s_bytes = hex::decode(signature_s_hex).unwrap();
    let message_bytes = hex::decode(message_hex).unwrap();
    let pub_key_x_bigint = BigInt::from_str_radix(pub_key_x_hex, 16).unwrap();
    let pub_key_y_bigint = BigInt::from_str_radix(pub_key_y_hex, 16).unwrap();
    let zengo_pub_key = Point::<Ed25519>::from_coords(
        &pub_key_x_bigint,
        &pub_key_y_bigint
    ).unwrap();

    let zengo_signature: ZengoSignature = ZengoSignature {
        R: Point::from_bytes(signature_r_bytes.as_slice()).unwrap(),
        s: Scalar::from_bytes(signature_s_bytes.as_slice()).unwrap(),
    };
    // This check is just to make sure the above conversions are done correctly:
    assert!(zengo_signature.verify(&message_bytes, &zengo_pub_key).is_ok());

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&signature_r_bytes);
    sig_bytes[32..].copy_from_slice(&signature_s_bytes);
    let bip32_signature: Signature<Vec<u8>> = Signature::from_bytes(sig_bytes);

    let chain_code_bytes = hex::decode(chain_code_hex).unwrap();
    //This is the main function we want to test:
    let pub_key_crate = create_public_key_ed25519_bip32(zengo_pub_key, chain_code_bytes);
    assert!(pub_key_crate.verify(&message_bytes, &bip32_signature));
}

#[test]
fn test_hd_derivations() {
    let master_public_key_bytes = [
        41, 9, 42, 231, 181, 54, 70, 117, 106, 129, 35, 18, 215, 174, 142, 187, 186, 189, 125,
        129, 103, 131, 219, 52, 59, 89, 213, 14, 180, 27, 125, 250,
    ];
    let master_chain_code_bytes = [
        245, 182, 135, 71, 224, 139, 206, 15, 200, 27, 106, 253, 197, 91, 155, 228, 38, 58,
        116, 150, 154, 116, 219, 141, 107, 189, 158, 80, 10, 82, 202, 13,
    ];
    let path = "1/0/3";
    let master_public_key: GE = GE::from_bytes(&master_public_key_bytes).unwrap();
    let chain_code_scalar = FE::from_bytes(&master_chain_code_bytes).unwrap();
    let chain_code = chain_code_scalar * GE::generator();
    let (_child_key_legacy,
        _child_tweak_legacy,
        _child_chain_code_legacy
    ) = get_legacy_hd_key(&master_public_key, path, chain_code.clone());

    let (child_key_bip32, child_chain_code_bip32) =
        derive_child_by_crate_ed25519_bip32(
            master_public_key_bytes,
            master_chain_code_bytes,
            path.to_string()
        );
    let (child_key_core, child_chain_code_core) =
        derive_child_by_crate_ed25519_bip32_core(
            master_public_key_bytes,
            master_chain_code_bytes,
            path.to_string()
        );

    /* Try crates with bytes export of the legacy key data:
    let mut master_bytes: [u8;32]  = [0u8; 32];
    master_bytes.copy_from_slice(&master_public_key.to_bytes(false).iter().as_slice()[0..32]);
    let mut master_cc: [u8;32] = [0u8; 32];
    master_cc.copy_from_slice(&chain_code.to_bytes(false).iter().as_slice()[0..32]);
    let (child_key_bip32, child_chain_code_bip32) = derive_child_by_crate_ed25519_bip32(master_bytes, master_cc, path.to_string());
    let (child_key_core, child_chain_code_core) = derive_child_by_crate_ed25519_bip32_core(master_bytes, master_cc, path.to_string());
     */

    assert_eq!(child_key_bip32, child_key_core);
    assert_eq!(child_chain_code_bip32, child_chain_code_core);

    let (_new_lib_child,
        _new_lib_tweak,
        new_lib_cc
    ) = hd_keys::get_hd_key_by_crate(master_public_key, path, master_chain_code_bytes.to_vec());
    assert_eq!(hex::encode(new_lib_cc), child_chain_code_bip32);
    /*
    This fails because derive_child_by_crate_ed25519_bip32 does not do final addition operation
    as documented in BIP32: "The returned child key Ki is point(parse256(IL)) + Kpar."
    See here: https://en.bitcoin.it/wiki/BIP_0032#Public_parent_key_%E2%86%92_public_child_key
     */
    //assert_eq!(hex::encode(new_lib_child.to_bytes(false).to_vec()), child_key_bip32);

    /*
    These fail because legacy does not comply with third party crates. As said above, mainly
    because legacy code considers chain_code as 33 bytes and also represents index number as
    a varying length bytes (from 1 to 4 bytes):

    let child_key_legacy_hex: String = hex::encode(child_key_legacy.to_bytes(false).to_vec());
    let child_chain_code_legacy_hex = hex::encode(child_chain_code_legacy);
    assert_eq!(child_key_legacy_hex, child_key_bip32);
    assert_eq!(child_chain_code_legacy_hex, child_chain_code_bip32);
    */
}

