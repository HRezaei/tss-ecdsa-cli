extern crate curv;
extern crate hex;
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;
extern crate serde_json;

use std::time;

use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{
    BigInt,
    arithmetic::{BasicOps, Converter, Modulo}
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use multi_party_ecdsa::utilities::mta::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use curv::elliptic::curves::{Point, Secp256k1};
use paillier::EncryptionKey;
use sha2::Sha256;

use crate::common::{Params, Client};
use crate::ecdsa::{CURVE_NAME, FE, GE};

#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct TupleKey {
    pub first: String,
    pub second: String,
    pub third: String,
    pub fourth: String,
}

pub fn sign(
    addr: String,
    party_keys: Keys,
    shared_keys: SharedKeys,
    party_id: u16,
    vss_scheme_vec: &mut Vec<VerifiableSS<Secp256k1>>,
    paillier_key_vector: Vec<EncryptionKey>,
    y_sum: &GE,
    params: &Params,
    message: &[u8],
    f_l_new: &FE,
    sign_at_path: bool,
) -> Value {
    let client_purpose = "sign".to_string();

    let delay = time::Duration::from_millis(25);
    let client = Client::new(client_purpose, CURVE_NAME, addr.clone(), delay, (*params).clone());
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();

    let (party_num_int, uuid) = (client.party_number, client.uuid.clone());

    let debug = json!({
        "manager_addr": &addr,
        "party_num": party_num_int,
        "uuid": uuid,
        "curve": CURVE_NAME
    });
    println!("{}", serde_json::to_string_pretty(&debug).unwrap());

    // round 0: collect signers IDs
    let mut signers_vec: Vec<u16> = client.exchange_data(THRESHOLD+1, "round0", party_id - 1);

    if sign_at_path == true {
        // optimize!
        let g: GE = Point::<Secp256k1>::generator().to_point();
        // apply on first commitment for leader (leader is party with num=1)
        let com_zero_new = vss_scheme_vec[0].commitments[0].clone() + g * f_l_new;
        // println!("old zero: {:?}, new zero: {:?}", vss_scheme_vec[0].commitments[0], com_zero_new);
        // get iterator of all commitments and skip first zero commitment
        let mut com_iter_unchanged = vss_scheme_vec[0].commitments.iter();
        com_iter_unchanged.next().unwrap();
        // iterate commitments and inject changed commitments in the beginning then aggregate into vector
        let com_vec_new = (0..vss_scheme_vec[1].commitments.len())
            .map(|i| {
                if i == 0 {
                    com_zero_new.clone()
                } else {
                    com_iter_unchanged.next().unwrap().clone()
                }
            })
            .collect::<Vec<GE>>();
        let new_vss = VerifiableSS {
            parameters: vss_scheme_vec[0].parameters.clone(),
            commitments: com_vec_new,
        };
        // replace old vss_scheme for leader with new one at position 0
        //    println!("comparing vectors: \n{:?} \nand \n{:?}", vss_scheme_vec[0], new_vss);

        vss_scheme_vec.remove(0);
        vss_scheme_vec.insert(0, new_vss);
        //    println!("NEW VSS VECTOR: {:?}", vss_scheme_vec);
    }

    let mut private = PartyPrivate::set_private(party_keys.clone(), shared_keys);

    if sign_at_path == true {
        if party_num_int == 1 {
            // update u_i and x_i for leader
            private = private.update_private_key(&f_l_new, &f_l_new);
        } else {
            // only update x_i for non-leaders
            private = private.update_private_key(&FE::zero(), &f_l_new);
        }
    }

    let sign_keys = SignKeys::create(
        &private,
        &vss_scheme_vec[signers_vec[(party_num_int - 1) as usize] as usize],
        signers_vec[(party_num_int - 1) as usize],
        &signers_vec,
    );

    //////////////////////////////////////////////////////////////////////////////
    let (com, decommit) = sign_keys.phase1_broadcast();
    let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &party_keys.ek, &[]);
    let round1_ans_vector = client.exchange_data(
        THRESHOLD + 1,
        "round1",
        (com.clone(), m_a_k.clone())
    );

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = round1_ans_vector
        .iter()
        .map(|x1| x1.0.clone())
        .collect();

    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            //     if signers_vec.contains(&(i as usize)) {
            let (_bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) = round1_ans_vector[(i-1) as usize].clone();
            m_a_vec.push(m_a_party_j);
            j = j + 1;
            //       }
        }
    }
    assert_eq!(signers_vec.len(), bc1_vec.len());

    //////////////////////////////////////////////////////////////////////////////
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<FE> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<FE> = Vec::new();
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &sign_keys.gamma_i,
                &paillier_key_vector[signers_vec[(i - 1) as usize] as usize],
                m_a_vec[j].clone(),
                &[]
            )
            .unwrap();
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &sign_keys.w_i,
                &paillier_key_vector[signers_vec[(i - 1) as usize] as usize],
                m_a_vec[j].clone(),
                &[]
            )
            .unwrap();
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j = j + 1;
        }
    }

    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            assert!(client.sendp2p(
                i.clone(),
                "round2",
                serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))
                    .unwrap(),
            )
            .is_ok());
            j = j + 1;
        }
    }

    let round2_ans_vec = client.poll_for_p2p(
        THRESHOLD + 1,
        "round2",
    );

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..THRESHOLD {
        //  if signers_vec.contains(&(i as usize)) {
        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);
        //     }
    }

    let mut alpha_vec: Vec<FE> = Vec::new();
    let mut miu_vec: Vec<FE> = Vec::new();

    let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        //        println!("mbproof p={}, i={}, j={}", party_num_int, i, j);
        if i != party_num_int {
            //            println!("verifying: p={}, i={}, j={}", party_num_int, i, j);
            let m_b = m_b_gamma_rec_vec[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &xi_com_vec[signers_vec[(i - 1) as usize] as usize],
                &vss_scheme_vec[signers_vec[(i - 1) as usize] as usize],
                signers_vec[(i - 1) as usize],
                &signers_vec,
            );
            //println!("Verifying client {}", party_num_int);
            assert_eq!(m_b.b_proof.pk.clone(), g_w_i);
            //println!("Verified client {}", party_num_int);
            j = j + 1;
        }
    }
    //////////////////////////////////////////////////////////////////////////////
    let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

    let mut delta_vec: Vec<FE> = client.exchange_data(THRESHOLD+1, "round3", delta_i);

    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    //////////////////////////////////////////////////////////////////////////////
    // decommit to gamma_i
    let mut decommit_vec: Vec<SignDecommitPhase1> = client.exchange_data(
        THRESHOLD+1,
        "round4",
        decommit
    );

    let decomm_i = decommit_vec.remove((party_num_int - 1) as usize);
    bc1_vec.remove((party_num_int - 1) as usize);
    let b_proof_vec = (0..m_b_gamma_rec_vec.len())
        .map(|i| &m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
    let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
        .expect("bad gamma_i decommit");

    // adding local g_gamma_i
    let R = R + decomm_i.g_gamma_i * &delta_inv;

    // we assume the message is already hashed (by the signer).
    let message_bn = BigInt::from_bytes(message);
    //    println!("message_bn INT: {}", message_bn);
    let message_int = BigInt::from_bytes(message);
    let two = BigInt::from(2);
    let message_bn = message_bn.modulus(&two.pow(256));
    let local_sig =
        LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) = local_sig.phase5a_broadcast_5b_zkproof();

    //phase (5A)  broadcast commit
    let mut commit5a_vec: Vec<Phase5Com1> = client.exchange_data(
        THRESHOLD+1,
        "round5",
        phase5_com
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    )> = client.exchange_data(
        THRESHOLD+1,
        "round6",
        (
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone()
        )
    );

    let decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_and_dlog_vec.clone();
    decommit5a_and_elgamal_and_dlog_vec.remove((party_num_int - 1) as usize);
    commit5a_vec.remove((party_num_int - 1) as usize);
    let phase_5a_decomm_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof<Secp256k1, Sha256>>>();
    let phase_5a_dlog_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
        .collect::<Vec<DLogProof<Secp256k1, Sha256>>>();
    let (phase5_com2, phase_5d_decom2) = local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_dlog_vec,
            &phase_5a_decom.V_i,
            &R.clone(),
        )
        .expect("error phase5");

    //////////////////////////////////////////////////////////////////////////////
    let mut commit5c_vec: Vec<Phase5Com2> = client.exchange_data(
        THRESHOLD + 1,
        "round7",
        phase5_com2
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    let mut decommit5d_vec: Vec<Phase5DDecom2> = client.exchange_data(
        THRESHOLD + 1,
        "round8",
        phase_5d_decom2
    );

    let phase_5a_decomm_vec_includes_i = (0..THRESHOLD + 1)
        .map(|i| decommit5a_and_elgamal_vec_includes_i[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = local_sig
        .phase5d(
            &decommit5d_vec,
            &commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    //////////////////////////////////////////////////////////////////////////////
    let mut s_i_vec: Vec<FE> = client.exchange_data(
        THRESHOLD + 1,
        "round9",
        s_i
    );

    s_i_vec.remove((party_num_int - 1) as usize);
    let sig = local_sig
        .output_signature(&s_i_vec)
        .expect("verification failed");
    //    println!(" \n");
    //    println!("party {:?} Output Signature: \n", party_num_int);
    //    println!("SIG msg: {:?}", sig.m);
    //    println!("R: {:?}", sig.r);
    //    println!("s: {:?} \n", sig.s);
    //    println!("child pubkey: {:?} \n", y_sum);

    //    println!("pubkey: {:?} \n", y_sum);
    //    println!("verifying signature with public key");
    verify(&sig, &y_sum, &message_bn).expect("false");
    //    println!("verifying signature with child pub key");
    //    verify(&sig, &new_key, &message_bn).expect("false");

    //    println!("{:?}", sig.recid.clone());
    //    print(sig.recid.clone()

    let ret_dict = json!({
        "r": sig.r.to_bigint().to_str_radix(16),
        "s": sig.s.to_bigint().to_str_radix(16),
        "status": "signature_ready",
        "recid": sig.recid.clone(),
        "x": &y_sum.x_coord().unwrap().to_str_radix(16),
        "y": &y_sum.y_coord().unwrap().to_str_radix(16),
        "msg_int": message_int,
    });

    ret_dict

    //    fs::write("signature".to_string(), sign_json).expect("Unable to save !");

    //    println!("Public key Y: {:?}", to_bitcoin_public_key(y_sum.get_element()).to_bytes());
    //    println!("Public child key X: {:?}", &new_key.x_coor());
    //    println!("Public child key Y: {:?}", &new_key.y_coor());
    //    println!("Public key big int: {:?}", &y_sum.bytes_compressed_to_big_int());
    //    println!("Public key ge: {:?}", &y_sum.get_element().serialize());
    //    println!("Public key ge: {:?}", PK::serialize_uncompressed(&y_sum.get_element()));
    //    println!("New public key: {:?}", &y_sum.x_coor);
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a Vec<String>,
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j = j + 1;
        }
    }
}

