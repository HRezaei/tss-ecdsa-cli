use std::fs;
use std::string::String;
use std::time::Duration;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Ed25519};
use multi_party_eddsa::Error;
use multi_party_eddsa::Error::InvalidKey;
use multi_party_eddsa::protocols::thresholdsig::{KeyGenDecommitMessage1, Keys, Parameters};
use sha2::Sha512;

use crate::common::{AEAD, aes_decrypt, aes_encrypt, AES_KEY_BYTES_LEN, Client, Params};
use crate::eddsa::{CURVE_NAME, FE, GE};


pub fn run_keygen(addr: &String, keys_file_path: &String, params: &Vec<&str>) {
    let THRESHOLD: u16 = params[0].parse::<u16>().unwrap();
    let PARTIES: u16 = params[1].parse::<u16>().unwrap();
    let delay = Duration::from_millis(25);
    let client_purpose = "keygen".to_string();

    let parameters = Parameters {
        threshold: THRESHOLD,
        share_count: PARTIES,
    };

    //signup:
    let tn_params = Params {
        threshold: THRESHOLD.to_string(),
        parties: PARTIES.to_string(),
    };

    let client = Client::new(client_purpose, CURVE_NAME, addr.clone(), delay, tn_params);
    let (party_num_int, uuid) = (client.party_number, client.uuid.clone());
    println!("number: {:?}, uuid: {:?}, curve: {:?}", party_num_int, uuid, CURVE_NAME);

    let party_keys = Keys::phase1_create(party_num_int);
    let (bc_i, decom_i) = party_keys.phase1_broadcast();

    // send commitment to ephemeral public keys, get round 1 commitments of other parties
    let bc1_vec = client.exchange_data(PARTIES, "round1", bc_i);

    // send ephemeral public keys and check commitments correctness
    let decommit_vector: Vec<KeyGenDecommitMessage1> = client.exchange_data(PARTIES, "round2", decom_i);

    let parties_public_key_vector: Vec<GE> = decommit_vector
        .iter()
        .map(|x| x.y_i.clone())
        .collect();

    let blind_vec: Vec<BigInt> = decommit_vector
        .iter()
        .map(|x| x.blind_factor.clone())
        .collect();

    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=PARTIES {
        if i != party_num_int {
            let decommit_j_y: GE = parties_public_key_vector[(i-1) as usize].clone();
            let key_bn: BigInt = (decommit_j_y * party_keys.keypair.expended_private_key.private_key.clone()).x_coord().unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
        }
    }

    let (head, tail) = parties_public_key_vector.split_at(1);
    let public_key = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    let key_gen_parties_indices = (0..PARTIES)
        .map(|i| i + 1)
        .collect::<Vec<u16>>();

    let (vss_scheme, secret_shares) = party_keys
        .phase1_verify_com_phase2_distribute(
            &parameters, &blind_vec, &parties_public_key_vector, &bc1_vec, &key_gen_parties_indices
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(client.sendp2p(
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
            )
                .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = client.poll_for_p2p(
        PARTIES,
        "round3",
    );

    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out[..]);
            let out_fe = FE::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    // round 4: send vss commitments and collect that of other parties
    let vss_scheme_vec = client.exchange_data(PARTIES, "round4", vss_scheme);

    let shared_keys = party_keys
        .phase2_verify_vss_construct_keypair(
            &parameters,
            &parties_public_key_vector,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    let dlog_proof = DLogProof::prove(&shared_keys.x_i);

    // round 5: send dlog proof
    let dlog_proof_vector = client.exchange_data(PARTIES, "round5", dlog_proof);

    verify_dlog_proofs(&parameters, &dlog_proof_vector, &parties_public_key_vector)
        .expect("bad dlog proof");

    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        public_key,
    ))
        .unwrap();

    fs::write(keys_file_path, keygen_json).expect("Unable to save !");
}


pub fn verify_dlog_proofs(
    params: &Parameters,
    dlog_proofs_vec: &[DLogProof<Ed25519, Sha512>],
    y_vec: &[GE],
) -> Result<(), Error> {
    assert_eq!(y_vec.len(), usize::from(params.share_count));
    assert_eq!(dlog_proofs_vec.len(), usize::from(params.share_count));

    let xi_dlog_verify =
        (0..y_vec.len()).all(|i| DLogProof::verify(&dlog_proofs_vec[i]).is_ok());

    if xi_dlog_verify {
        Ok(())
    } else {
        Err(InvalidKey)
    }
}