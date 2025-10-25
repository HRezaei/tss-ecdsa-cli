
#[cfg(test)]
mod hd_derivation {
    use std::convert::{TryInto};
    use std::str::FromStr;
    use bip32::{
        ChildNumber,
        ExtendedKeyAttrs,
        ExtendedPublicKey,
        KeyFingerprint,
        PublicKeyBytes,
        XPrv,
        XPub
    };
    use bip32::secp256k1::elliptic_curve::PublicKey;
    use bip32::secp256k1::ecdsa::VerifyingKey;
    use bip32::secp256k1::Secp256k1;
    use bitcoin::hex::DisplayHex;
    use curv::arithmetic::{Converter};
    use curv::BigInt;
    use hex::ToHex;
    use crate::hd_keys;
    use crate::protocols::ecdsa::{FE, GE};
    use coins_bip32::prelude::{XPub as Bip32CoinsXPub};
    use coins_bip32::primitives::{
        XKeyInfo,
        KeyFingerprint as CoinsBip32KeyFingerprint,
        Hint,
        ChainCode as CoinsBip32ChainCode
    };
    use coins_bip32::prelude::*;
    use coins_bip32::prelude::k256::elliptic_curve::sec1::FromEncodedPoint;
    use coins_bip32::xkeys::Parent;

    fn decompress_point(point_bytes: [u8;33]) -> (Vec<u8>, Vec<u8>) {
        use k256::{EncodedPoint, PublicKey};

        // Parse compressed pubkey to PublicKey
        let encoded_point = EncodedPoint::from_bytes(&point_bytes)
            .expect("Invalid encoded point");
        let pub_key = PublicKey::from_encoded_point(&encoded_point).unwrap();
        let binding = pub_key.to_encoded_point(false);

        let child_x = binding.x().unwrap();
        let child_y = binding.y().unwrap();

        (child_x.to_vec(), child_y.to_vec())
    }

    fn derive_child_by_crate_bip32(pub_key: Vec<u8>, chain_code: Vec<u8>, path: String) -> (String, String, String) {
        let finger_print = KeyFingerprint::from([0u8; 4]);
        let pub_key_bytes: PublicKeyBytes = pub_key.try_into().unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes).unwrap();

        let pub_key_crate = XPub::new(verifying_key, ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: finger_print,
            child_number: ChildNumber(10), //This is not important during HD derivation
            chain_code: chain_code.try_into().unwrap(),
        });

        let path_numbers = path.split('/')
            .map(|s| s.parse::<u32>().expect("Invalid number"));

        let mut child_key = pub_key_crate;
        for child_path in path_numbers {
            let child_num = ChildNumber(child_path);
            child_key = child_key.derive_child(child_num).unwrap();
        }

        let child_x: String = child_key.public_key().to_encoded_point(false).x().unwrap()
            .encode_hex();
        let child_y: String = child_key.public_key().to_encoded_point(false).y().unwrap()
            .encode_hex();

        (child_x, child_y, child_key.attrs().chain_code.encode_hex())
    }

    fn derive_child_by_crate_hdwallet(pub_key: Vec<u8>, chain_code: Vec<u8>, path: String) -> (String, String, String) {

        let finger_print = KeyFingerprint::from([0u8; 4]);
        let pub_key_bytes: PublicKeyBytes = pub_key.try_into().unwrap();
        let public_key: PublicKey<Secp256k1> = PublicKey::from_sec1_bytes(pub_key_bytes.to_vec().as_slice()).unwrap();
        let master_key = ExtendedPublicKey::new(public_key, ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: finger_print,
            child_number: ChildNumber(10), // This is not important for HD
            chain_code: chain_code.try_into().unwrap(),
        });

        let path_numbers = path.split('/')
            .map(|s| s.parse::<u32>().expect("Invalid number"));

        let mut child = master_key;
        for child_path in path_numbers {
            let child_num = ChildNumber(child_path);
            child = child.derive_child(child_num).unwrap();
        }

        let child_x: String = child.public_key().to_encoded_point(false).x().unwrap()
            .encode_hex();
        let child_y: String = child.public_key().to_encoded_point(false).y().unwrap()
            .encode_hex();

        (child_x, child_y, child.attrs().chain_code.encode_hex())
    }

    fn derive_child_by_coins_bip32(pub_key: Vec<u8>, chain_code: Vec<u8>, path: String) -> (String, String, String) {
        let finger_print = CoinsBip32KeyFingerprint::from([0u8; 4]);
        let pub_key_bytes: PublicKeyBytes = pub_key.try_into().unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes).unwrap();
        let mut chain_code_32_bytes = [0u8; 32]; // Initialize with zeroes
        chain_code_32_bytes[..chain_code.len()].copy_from_slice(chain_code.as_slice()); // Copy as much as fits
        let pub_key_crate = Bip32CoinsXPub::new(verifying_key, XKeyInfo {
            depth: 0,
            parent: finger_print,
            chain_code: CoinsBip32ChainCode::from(chain_code_32_bytes),
            index: 0,
            hint: Hint::Legacy,
        });

        let path_numbers = path.split('/')
            .map(|s| s.parse::<u32>().expect("Invalid number"));

        let mut child = pub_key_crate;
        for child_num in path_numbers {
            child = child.derive_child(child_num).unwrap();
        }

        let (child_x, child_y) = decompress_point(child.to_sec1_bytes());
        let xkey_info: &XKeyInfo = child.as_ref();

        (hex::encode(child_x), hex::encode(child_y), hex::encode(xkey_info.chain_code.0))
    }

    #[test]
    fn test_pubkey() {
        let original_x = BigInt::from_hex(
            "d6f3c325eb3fda7061983141278484c0dd452a6702fd537b89c09ddf2b6f3238").unwrap();
        let original_y = BigInt::from_hex(
            "4e12adae75c29b29cc094fd3d94aa401ea646104f0d1ae3c59f710ec92640e21").unwrap();
        let original_public_key: GE = GE::from_coords(&original_x, &original_y).expect("Failed to create the point");

        let path = "1/2/3";
        let expected_pubkey_x = "e891363052c09185814e92ce7a1a1946631dc53d058a01176fcf27a66b5674c2";
        let expected_pubkey_y = "cfbe0a84b7f7c49b5bb2a48999a761fc6c5dd6526aa79a58d4029865ef7d4a17";
        let chain_code= GE::generator().to_point();
        let (public_key_child,
            _tweak_child,
            _chain_code_child
        ) = hd_keys::get_legacy_hd_key(&original_public_key, path, chain_code);

        assert_eq!(public_key_child.x_coord().unwrap().to_hex(), expected_pubkey_x);
        assert_eq!(public_key_child.y_coord().unwrap().to_hex(), expected_pubkey_y);
    }

    #[test]
    fn test_hd_with_crate(){
        let path = "1/0/2";
        let original_x = BigInt::from_hex(
            "d6f3c325eb3fda7061983141278484c0dd452a6702fd537b89c09ddf2b6f3238").unwrap();
        let original_y = BigInt::from_hex(
            "4e12adae75c29b29cc094fd3d94aa401ea646104f0d1ae3c59f710ec92640e21").unwrap();
        let original_public_key: GE = GE::from_coords(&original_x, &original_y)
            .expect("Failed to create the point");

        /*
        Considering the current version of Trepca's HD as ground truth, these are the values it
        produces. I keep them to make sure in the future, any change in legacy code, yields the
        same result.
        */
        let trepca_pubkey_x = "f0455a6fb01d03fe0ac0259bc174ebe50cd471a641fe11b38661950fdd5477b9";
        let trepca_pubkey_y = "93ee707745153a12bfe6b72f2965398fc294376aae55ffe828dcc3664007c240";
        let trepca_pubkey_chain_code = "02ef8d7ed7df15320b79e1c012b6981e2457eafba49eb9b4bc21a2123d56e3e16a";
        let trepca_tweak = "743cc8005e41fa3b98d9c2bc57499c97cd074e58ae56953030c77018b9d1a4a1";

        /*
        However, the above values don't match the output of third party crates, mainly because
        legacy code considers chain_code as 33 bytes and also represents index number as a varying
        length bytes (from 1 to 4 bytes).
        Thus, considering the current version of bip32 crate as ground truth, these are the values
        it produces. I keep them to make sure in the future, any update/upgrade in that crate,
        yields the same result.
         */
        let expected_pubkey_x = "dfd4557dc4d15178c373240d0033ab1a66abfe796c3a4485240496a82b0fda68";
        let expected_pubkey_y = "9263b6e81791a678b29d4d3b5a56437fd80474d33168ead877fccdd6652f6954";
        let expected_chain_code = "0f5db0d138cc474304dd5b9c822c32671b358955351d2e96095820d6075c3988";
        //None of crates return tweak so we cannot test this:
        let _expected_tweak = "de7599ecc740b86e30ccc283d77545f1fa48db3edd0bb970601e93a2dde725c4";

        let chain_code_scalar = FE::from(1);
        let chain_code_point = chain_code_scalar.clone() * GE::generator().to_point();
        let (legacy_child,
            legacy_tweak,
            legacy_chain_code
        ) = hd_keys::get_legacy_hd_key(&original_public_key, path, chain_code_point.clone());

        let legacy_child_x = legacy_child.x_coord().unwrap().to_hex();
        let legacy_child_y = legacy_child.y_coord().unwrap().to_hex();
        let legacy_chain_code = hex::encode(legacy_chain_code);
        let legacy_tweak = hex::encode(legacy_tweak.to_bytes().to_vec());

        let original_pubkey_bytes = original_public_key.to_bytes(true).to_vec();
        let chain_code_bytes = chain_code_scalar.to_bytes().to_vec();

        let (bip32_x, bip32_y, bip32_chain_code) = derive_child_by_crate_bip32(
            original_pubkey_bytes.clone(),
            chain_code_bytes.clone(),
            path.to_string()
        );
        let (hd_wallet_x,
            hd_wallet_y,
            hd_wallet_chain_code
        ) = derive_child_by_crate_hdwallet(
            original_pubkey_bytes.clone(),
            chain_code_bytes.clone(),
            path.to_string()
        );
        let (coins_x, coins_y, coins_chain_code) = derive_child_by_coins_bip32(
            original_pubkey_bytes,
            chain_code_bytes.clone(),
            path.to_string()
        );

        assert_eq!(coins_x, bip32_x);
        assert_eq!(coins_y, bip32_y);
        assert_eq!(coins_chain_code, bip32_chain_code);

        assert_eq!(hd_wallet_x, bip32_x);
        assert_eq!(hd_wallet_y, bip32_y);
        assert_eq!(hd_wallet_chain_code, bip32_chain_code);

        assert_eq!(bip32_x, expected_pubkey_x);
        assert_eq!(bip32_y, expected_pubkey_y);
        assert_eq!(bip32_chain_code, expected_chain_code);

        assert_eq!(legacy_child_x, trepca_pubkey_x);
        assert_eq!(legacy_child_y, trepca_pubkey_y);
        assert_eq!(legacy_chain_code, trepca_pubkey_chain_code);
        assert_eq!(legacy_tweak, trepca_tweak);

        let (new_lib_child,
            _new_lib_tweak,
            new_lib_cc
        ) = hd_keys::get_hd_child_by_crate(original_public_key, path, chain_code_bytes);
        assert_eq!(new_lib_child.x_coord().unwrap().to_hex(), expected_pubkey_x);
        assert_eq!(new_lib_child.y_coord().unwrap().to_hex(), expected_pubkey_y);
        assert_eq!(hex::encode(new_lib_cc), expected_chain_code);

        /*
        These fail because legacy does not comply with third party crates. As said above, mainly
        because legacy code considers chain_code as 33 bytes and also represents index number as
        a varying length bytes (from 1 to 4 bytes).
         */
        //assert_eq!(expected_pubkey_x, legacy_child_x);
        //assert_eq!(expected_pubkey_y, legacy_child_y);
    }

    fn pub_key_coords(xpub: bitcoin::bip32::Xpub) -> (String, String) {
        let uncompressed = xpub.public_key.serialize_uncompressed();

        // Slice out x and y coordinates
        let x = &uncompressed[1..33]; // bytes 1 to 32
        let y = &uncompressed[33..65]; // bytes 33 to 64

        (hex::encode(x), hex::encode(y))
    }

    #[test]
    fn test_hd_derivation_based_on_bip32_docs() {
        /**
        Reference keys are copied from here:
        https://en.bitcoin.it/wiki/BIP_0032#Test_Vectors
        */
        use bitcoin::bip32::{Xpriv, DerivationPath};
        use bitcoin::bip32::Xpub;
        use bitcoin::network::Network;
        use bitcoin::secp256k1::Secp256k1 as BitcoinSecp256k1;
        use hex::decode;

        let seed_hex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
        let seed_bytes = decode(seed_hex).expect("Invalid hex");

        let secp = BitcoinSecp256k1::new();

        // Derive master key (m)
        let master = Xpriv::new_master(Network::Bitcoin, &seed_bytes).expect("Master key error");
        let master_xprv = master.to_string();
        let master_pub_key = Xpub::from_priv(&secp, &master);

        let expected_master_key = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
        let expected_master_pub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";

        assert_eq!(expected_master_key, master_xprv);
        assert_eq!(expected_master_pub, master_pub_key.to_string());

        // Derive child key at m/0
        let bip32_path = DerivationPath::from_str("m/0").unwrap();
        let child = master.derive_priv(&secp, &bip32_path).expect("Child key error");
        let child_private_key = child.to_string();
        let child_pub_key = Xpub::from_priv(&secp, &child);

        let expected_child_key = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt";
        let expected_child_pub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";

        assert_eq!(expected_child_key, child_private_key);
        assert_eq!(expected_child_pub, child_pub_key.to_string());

        // Slice out x and y coordinates
        let (child_pub_x, child_pub_y) = pub_key_coords(child_pub_key); // bytes 1 to 32
        let child_pub_chain_code = hex::encode(child_pub_key.chain_code);
        println!("\nChild public key coordinates:");
        println!("X = {}", child_pub_x);
        println!("Y = {}", child_pub_y);


        let (x, y) = pub_key_coords(master_pub_key);
        println!("\nMaster public key coordinates:");
        println!("X = {}", x);
        println!("Y = {}", y);

        let secp2 = BitcoinSecp256k1::new();
        let child_from_pub = master_pub_key.derive_pub(&secp2, &bip32_path).expect("Child key error");
        let (x, y) = pub_key_coords(child_from_pub);
        println!("\nChild public key from public key coordinates:");
        println!("X = {}", x);
        println!("Y = {}", y);
        //###################################################
        let master_pub_key_bytes = master_pub_key.public_key.serialize();
        let original_public_key: GE = GE::from_bytes(master_pub_key_bytes.as_slice()).unwrap();

        println!("\nMaster public key coordinates in our lib:");
        println!("x: {:?}", original_public_key.x_coord().unwrap().to_hex());
        println!("y: {:?}", original_public_key.y_coord().unwrap().to_hex());

        //let chain_code_scalar = FE::from(1);
        //let chain_code_point = chain_code_scalar.clone() * GE::generator().to_point();
        //println!("cc len: {:?}", &chain_code_point.to_bytes(true).len());
        // The above code prints 33 whilst bip32 spec defines chain_code as 32 bytes. This is one of
        // the reasons why Trepca's HD differs from third party crates.
        let path = "0";

        let (bip32_child_x,
            bip32_child_y,
            bip32_child_chain_code
        ) = derive_child_by_crate_bip32(master_pub_key.public_key.serialize().to_vec(),
                                        master_pub_key.chain_code.to_bytes().to_vec(),
                                        path.to_string()
        );

        assert_eq!(bip32_child_x, child_pub_x);
        assert_eq!(bip32_child_y, child_pub_y);
        assert_eq!(bip32_child_chain_code, child_pub_chain_code);

        let (hd_wallet_x,
            hd_wallet_y,
            hd_wallet_chain_code
        ) = derive_child_by_crate_hdwallet(master_pub_key.public_key.serialize().to_vec(),
                                           master_pub_key.chain_code.to_bytes().to_vec(),
                                           path.to_string()
        );
        assert_eq!(bip32_child_x, hd_wallet_x);
        assert_eq!(bip32_child_y, hd_wallet_y);
        assert_eq!(bip32_child_chain_code, hd_wallet_chain_code);

        let (coins_x,
            coins_y,
            coins_chain_code
        ) = derive_child_by_coins_bip32(master_pub_key.public_key.serialize().to_vec(),
                                        master_pub_key.chain_code.to_bytes().to_vec(),
                                        path.to_string()
        );
        assert_eq!(bip32_child_x, coins_x);
        assert_eq!(bip32_child_y, coins_y);
        assert_eq!(bip32_child_chain_code, coins_chain_code);
    }

    #[test]
    fn test_hardened_hd_derivation_based_on_bip32_docs() {
        /**
        Reference keys are copied from here:
        https://en.bitcoin.it/wiki/BIP_0032#Test_Vectors
        */
        use bitcoin::bip32::{Xpriv, DerivationPath};
        use bitcoin::bip32::Xpub;
        use bitcoin::network::Network;
        use bitcoin::secp256k1::Secp256k1 as BitcoinSecp256k1;
        use hex::decode;

        let seed_hex = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = decode(seed_hex).expect("Invalid hex");
        let secp = BitcoinSecp256k1::new();

        // Create master key (m)
        let master = Xpriv::new_master(Network::Bitcoin, &seed_bytes).expect("Master key error");
        let master_xprv = master.to_string();
        let master_pub_key = Xpub::from_priv(&secp, &master);

        let expected_master_key = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let expected_master_pub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        assert_eq!(expected_master_key, master_xprv);
        assert_eq!(expected_master_pub, master_pub_key.to_string());

        // Derive child key at m/0
        let path = "0'";
        let bip32_path = DerivationPath::from_str(("m/".to_owned() + path).as_str()).unwrap();
        let child = master.derive_priv(&secp, &bip32_path).expect("Child key error");
        let child_private_key = child.to_string();
        let child_pub_key = Xpub::from_priv(&secp, &child);

        let expected_child_key = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        let expected_child_pub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

        assert_eq!(expected_child_key, child_private_key);
        assert_eq!(expected_child_pub, child_pub_key.to_string());

        // Slice out x and y coordinates
        let (child_pub_x, child_pub_y) = pub_key_coords(child_pub_key); // bytes 1 to 32
        let child_pub_chain_code = hex::encode(child_pub_key.chain_code);

        let master_chain_code = master.chain_code.to_bytes().to_vec();
        let master_scalar = FE::from_bytes(&master.private_key.secret_bytes()).unwrap();

        let (
            child_pub_by_us,
            child_tweak,
            child_chain_code_by_us
        ) = hd_keys::get_hardened_hd_child_by_crate(
            master_scalar.clone(),
            path,
            master_chain_code.clone()
        );
        let child_pub_by_us_x = child_pub_by_us.x_coord().unwrap().to_hex();
        let child_pub_by_us_y = child_pub_by_us.y_coord().unwrap().to_hex();
        assert_eq!(child_pub_by_us_x, child_pub_x);
        assert_eq!(child_pub_by_us_y, child_pub_y);
        assert_eq!(child_chain_code_by_us.as_hex().to_string(), child_pub_chain_code);
        assert_eq!(child_tweak.as_hex().to_string(), child.private_key.secret_bytes().as_hex().to_string());
        //################################################### Try the last test vector:
        let path = "0'/1/2'/2/1000000000";
        let expected_child_pub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";
        let expected_child_prv = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";
        let expected_child_prv = XPrv::from_str(expected_child_prv).unwrap();
        let child_pub_key = Xpub::from_str(expected_child_pub).unwrap();
        let (expected_child_pub_x, expected_child_pub_y) = pub_key_coords(child_pub_key);
        let expected_child_chain_code = child_pub_key.chain_code.to_bytes().to_vec();

        let (
            child_pub_by_us,
            child_tweak,
            child_chain_code_by_us
        ) = hd_keys::get_hardened_hd_child_by_crate(master_scalar, path, master_chain_code);
        let child_pub_by_us_x = child_pub_by_us.x_coord().unwrap().to_hex();
        let child_pub_by_us_y = child_pub_by_us.y_coord().unwrap().to_hex();
        assert_eq!(child_pub_by_us_x, expected_child_pub_x);
        assert_eq!(child_pub_by_us_y, expected_child_pub_y);
        assert_eq!(child_chain_code_by_us, expected_child_chain_code);
        assert_eq!(child_tweak, expected_child_prv.private_key().to_bytes().to_vec());
    }
}


#[cfg(test)]
pub(crate) mod integration {
    use curv::arithmetic::Converter;
    use curv::BigInt;
    use crate::common::DKGSignScheme;
    use crate::protocols::ecdsa::{sum_of_fragment_files, FE, GE};
    use crate::tests::integration::{check_keygen_t_of_n, check_sign_t_of_n_generate, prepare_manager_and_keys};
    use crate::tests::{kill_manager, TestResourcesCleanUp};
    pub fn check_sig(
        r: &FE,
        s: &FE,
        msg: &BigInt,
        pk: &GE,
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

    pub fn verify_signature(
        signature_r_hex: String,
        signature_s_hex: String,
        message_hex: String,
        pub_key_x_hex: String,
        pub_key_y_hex: String
    ) {
        let r_bytes = hex::decode(signature_r_hex).unwrap();
        let r_scalar = FE::from_bytes(r_bytes.as_slice()).unwrap();

        let s_bytes = hex::decode(signature_s_hex).unwrap();
        let s_scalar = FE::from_bytes(s_bytes.as_slice()).unwrap();

        let msg_bigint = BigInt::from_str_radix(message_hex.as_str(), 16).unwrap();

        let x_bigint = BigInt::from_str_radix(pub_key_x_hex.as_str(), 16).unwrap();
        let y_bigint = BigInt::from_str_radix(pub_key_y_hex.as_str(), 16).unwrap();
        let public_key = GE::from_coords(&x_bigint, &y_bigint).unwrap();

        check_sig(&r_scalar, &s_scalar, &msg_bigint, &public_key);
    }

    #[test]
    fn test_keygen_2_of_5() {
        check_keygen_t_of_n(2, 5, DKGSignScheme::ECDSA);
    }

    #[test]
    fn test_keygen_1_of_3() {
        check_keygen_t_of_n(1, 3, DKGSignScheme::ECDSA);
    }

    #[test]
    fn test_sign_1_of_3() {
        check_sign_t_of_n_generate(1, 3, DKGSignScheme::ECDSA);
    }

    #[test]
    fn test_sign_2_of_5() {
        check_sign_t_of_n_generate(2, 5, DKGSignScheme::ECDSA);
    }

    #[test]
    fn test_keys_summation() {
        match prepare_manager_and_keys(1, 3, DKGSignScheme::ECDSA) {
            Some((manager, keyfiles, _manager_url)) => {
                kill_manager(manager);

                let _clean_up = TestResourcesCleanUp {
                    keyfiles: keyfiles.clone(),
                    manager: None
                };
                match sum_of_fragment_files(keyfiles) {
                    Ok((summation_pub_key, files_pub_key, _)) => {
                        assert_eq!(summation_pub_key, files_pub_key);
                    }
                    Err(error) => {
                        assert!(false, "Error in summing keys: {}", error);
                    }
                }
            }
            None => assert!(false, "Failed to prepare manager and key files.")
        }
    }
}