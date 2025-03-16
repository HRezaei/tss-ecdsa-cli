use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};

#[cfg(test)]
mod tests {
    use curv::arithmetic::Converter;
    use curv::BigInt;
    use curv::elliptic::curves::{Point, Secp256k1};
    use crate::hd_keys;

    #[test]
    fn test_pubkey() {
        let original_x = BigInt::from_hex(
            "d6f3c325eb3fda7061983141278484c0dd452a6702fd537b89c09ddf2b6f3238").unwrap();
        let original_y = BigInt::from_hex(
            "4e12adae75c29b29cc094fd3d94aa401ea646104f0d1ae3c59f710ec92640e21").unwrap();
        let original_public_key: Point<Secp256k1> = Point::<Secp256k1>::from_coords(&original_x, &original_y).expect("Failed to create the point");

        let path = "1/2/3";
        let expected_pubkey_x = "e891363052c09185814e92ce7a1a1946631dc53d058a01176fcf27a66b5674c2";
        let expected_pubkey_y = "cfbe0a84b7f7c49b5bb2a48999a761fc6c5dd6526aa79a58d4029865ef7d4a17";
        let chain_code= Point::<Secp256k1>::generator().to_point();
        let (public_key_child, _) = hd_keys::get_hd_key(&original_public_key, path, chain_code);

        assert_eq!(public_key_child.x_coord().unwrap().to_hex(), expected_pubkey_x);
        assert_eq!(public_key_child.y_coord().unwrap().to_hex(), expected_pubkey_y);
    }

}



#[allow(dead_code)]
pub fn check_sig(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) {
    use libsecp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_bytes(msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.to_bytes(false).to_vec();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::parse_standard_slice(compact.as_slice()).unwrap();

    let is_correct = verify(&msg, &secp_sig, &pk);
    assert!(is_correct);
}
