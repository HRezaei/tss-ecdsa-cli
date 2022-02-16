use std::time::Duration;
use curv::cryptographic_primitives::hashing::Digest;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Curve, Point, Scalar};
use crate::common::Client;
use crate::eddsa::signer::exchange_data;

pub mod ecdsa;
pub mod eddsa;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey
}

pub fn verify_dlog_proofs<E: Curve, H:Digest + Clone>(
    share_count: usize,
    dlog_proofs_vec: &[DLogProof<E, H>],
    y_vec_len: usize,
) -> Result<(), Error> {
    assert_eq!(y_vec_len, share_count);
    assert_eq!(dlog_proofs_vec.len(), share_count);

    let xi_dlog_verify =
        (0..y_vec_len).all(|i| DLogProof::verify(&dlog_proofs_vec[i]).is_ok());

    if xi_dlog_verify {
        Ok(())
    } else {
        Err(Error::InvalidKey)
    }
}



fn generate_shared_chain_code<E: Curve, H: Digest + Clone>(client: Client,
                                                           party_num_int: u16,
                                                           parties_num: u16,
                                                           uuid: String,
                                                           delay: Duration,
                                                           share_count: usize
) -> Scalar<E>
{
    let chain_code_i = Scalar::<E>::random();
    let dlog_proof: DLogProof<E, H> = DLogProof::prove(&chain_code_i);

    // round 0: send dlog proof
    let dlog_proof_vec = exchange_data(
        client.clone(),
        party_num_int,
        parties_num,
        uuid.clone(),
        "round0_chain_code",
        delay,
        dlog_proof
    );

    verify_dlog_proofs(share_count, &dlog_proof_vec, parties_num as usize)
        .expect("bad dlog proof for chain code");

    // round 1: send chain code and collect chain code of all parties
    let chain_codes = exchange_data(
        client,
        party_num_int,
        parties_num,
        uuid,
        "round1_chain_code",
        delay,
        chain_code_i
    );

    let all_commitments_are_satisfied = chain_codes.iter()
        .enumerate()
        .all(|(index, x)| (x * Point::<E>::generator()) == dlog_proof_vec[index].pk);

    assert!(all_commitments_are_satisfied);

    let (head, tail) = chain_codes.split_at(1);
    let chain_code = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    chain_code
}