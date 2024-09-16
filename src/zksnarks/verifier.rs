use crate::error::{Error, Result};
use base64::prelude::*;
use bellman::groth16::{prepare_verifying_key, verify_proof, Parameters, VerifyingKey};
use bls12_381::Bls12;
use bls12_381::Scalar;
use bytes::{self, Buf};
use ff::PrimeField;
use std::io::Cursor;

pub fn verify_know_root_base64_proof(zktoken: &str) -> Result<()> {
    let data: Vec<&str> = zktoken.split_terminator(".").collect();
    let [proof_base64, verification_key_base64, ..] = data[..] else {
        return Err(Error::Token(format!("Invalid token {zktoken}")));
    };

    let proof = BASE64_STANDARD.decode(proof_base64)?;
    let vk_bytes = BASE64_STANDARD.decode(verification_key_base64)?;

    let reader = proof.reader();
    let proof: bellman::groth16::Proof<_> = bellman::groth16::Proof::<Bls12>::read(reader)?;

    let mut vk_reader = Cursor::new(vk_bytes);
    let vk = VerifyingKey::<Bls12>::read(&mut vk_reader)?;

    // Prepare the verifying key
    let pvk = prepare_verifying_key(&vk);

    let public_inputs = [];
    let result = verify_proof(&pvk, &proof, &public_inputs);

    result.map_err(Error::from)
}

pub fn verify_proof_secret_number_bigger_than_base64(zktoken: &str, threshold: u32) -> Result<()> {
    let data: Vec<&str> = zktoken.split_terminator(".").collect();
    let [proof_base64, verification_key_base64, ..] = data[..] else {
        return Err(Error::Token(format!("Invalid token {zktoken}")));
    };

    let proof = BASE64_STANDARD.decode(proof_base64)?;
    let vk_bytes = BASE64_STANDARD.decode(verification_key_base64)?;

    let reader = proof.reader();
    let proof: bellman::groth16::Proof<_> = bellman::groth16::Proof::<Bls12>::read(reader)?;

    let mut vk_reader = Cursor::new(vk_bytes);
    let vk = VerifyingKey::<Bls12>::read(&mut vk_reader)?;

    // Prepare the verifying key
    let pvk = prepare_verifying_key(&vk);

    let public_inputs = vec![Scalar::from_u128(threshold as u128)];
    let result = verify_proof(&pvk, &proof, &public_inputs);

    result.map_err(Error::from)
}
