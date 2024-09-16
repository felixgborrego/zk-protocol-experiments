use crate::error::Result;
use crate::zksnarks::zkcircuits;
use base64::prelude::*;
use bellman::{
    self,
    groth16::{create_random_proof, prepare_verifying_key, verify_proof, Parameters},
};
use bls12_381::{Bls12, Scalar};
use bytes::BufMut;
use ff::PrimeField;
use rand::rngs::OsRng;
use std::io::Write;

/// generate the ZK proof
pub fn generate_prove_for_known_root_base64(x: u32, root: u32) -> Result<String> {
    let rng = &mut OsRng;

    let init_params: Parameters<Bls12> = zkcircuits::secret_root_init_params();

    let prover_circuit = zkcircuits::SquereRootCircuit {
        x: Some(Scalar::from_u128(x as u128)),
        root: Some(Scalar::from_u128(root as u128)),
    };

    let proof: bellman::groth16::Proof<_> =
        create_random_proof(prover_circuit, &init_params, rng).expect("Proof generation failed");

    let data = Vec::new();
    let mut writer = data.writer();
    proof.write(&mut writer)?;
    writer.flush()?;

    // Encode proof
    let data = writer.into_inner();
    let proof_base64 = BASE64_STANDARD.encode(&data);

    // Encode verifying key
    let vk = &init_params.vk;
    let mut vk_bytes = vec![];
    vk.write(&mut vk_bytes)?;
    let verify_key_base64 = BASE64_STANDARD.encode(vk_bytes);

    Ok(format!("{proof_base64}.{verify_key_base64}"))
}

pub fn generate_prove_for_secreet_number_base64(
    my_secret_value: u32,
    to_prove_bigger_than: u32,
) -> Result<String> {
    let rng = &mut OsRng;

    // let params: bellman::groth16::Parameters<_> = MyZKSecretNumberCircuit::init_params();
    let init_params: Parameters<Bls12> = zkcircuits::secret_number_init_params();

    println!("step 1!");
    let prover_circuit = zkcircuits::MyZKSecretNumberCircuit {
        secret_number: Some(Scalar::from_u128(my_secret_value as u128)),
        threshold: Some(Scalar::from_u128(to_prove_bigger_than as u128)),
    };

    println!("step 2!");
    let proof: bellman::groth16::Proof<_> =
        create_random_proof(prover_circuit, &init_params, rng).expect("Proof generation failed");

    let pvk = prepare_verifying_key(&init_params.vk);

    let public_inputs = vec![Scalar::from_u128(to_prove_bigger_than as u128)]; // Our threshold for passing grade
                                                                               //let public_inputs = [];
                                                                               //let public_inputs = [];
    let result = verify_proof(&pvk, &proof, &public_inputs);
    println!("Result before sending {result:?}");

    let data = Vec::new();
    let mut writer = data.writer();
    proof.write(&mut writer)?;
    writer.flush()?;

    // Encode proof
    let data = writer.into_inner();
    let proof_base64 = BASE64_STANDARD.encode(&data);

    // Encode verifying key
    let vk = &init_params.vk;
    let mut vk_bytes = vec![];
    vk.write(&mut vk_bytes)?;
    let verify_key_base64 = BASE64_STANDARD.encode(vk_bytes);

    Ok(format!("{proof_base64}.{verify_key_base64}"))
}
