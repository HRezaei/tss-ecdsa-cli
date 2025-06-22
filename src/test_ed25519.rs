#[cfg(test)]
mod tests {
    use ed25519_bip32::DerivationScheme;
    use ed25519_bip32::{XPub};
    use hex::ToHex;

    use curv::elliptic::curves::{Ed25519, Point, Scalar};
    use crate::common::hd_keys::{get_hd_key};

    type GE = Point<Ed25519>;
    type FE = Scalar<Ed25519>;
    fn pub_key_split(pub_key: XPub) -> (String, String) {
        let uncompressed = pub_key.public_key_slice();

        let x = &uncompressed[0..32]; // bytes 0 to 32
        let chain_code = &pub_key.chain_code()[0..32]; // bytes 0 to 32

        (hex::encode(x), hex::encode(chain_code))
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
            child_key = child_key.derive(DerivationScheme::V2, child_path).unwrap();
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
        let (child_key_legacy, child_chain_code_legacy) =
            get_hd_key(&master_public_key, path, chain_code.clone());

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

        let child_key_legacy_hex: String = child_key_legacy.to_bytes(false).iter().encode_hex();
        let child_chain_code_legacy_hex: String = child_chain_code_legacy.to_bytes().iter().encode_hex();
        assert_eq!(child_key_legacy_hex, child_key_bip32);
        assert_eq!(child_chain_code_legacy_hex, child_chain_code_bip32);
    }
}
