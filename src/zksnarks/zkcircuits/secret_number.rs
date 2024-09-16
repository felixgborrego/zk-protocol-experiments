use bellman::{
    self,
    groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    },
};
use bls12_381::{Bls12, Scalar};
use ff::{Field, PrimeField};
use rand::rngs::OsRng;

// Hold a Secret number that I want to prove is bigger than the threshold.
pub struct MyZKSecretNumberCircuit<F: Field> {
    pub secret_number: Option<F>,
    pub threshold: Option<F>,
}

pub fn secret_number_init_params() -> bellman::groth16::Parameters<Bls12> {
    let rng = &mut OsRng;
    let params: bellman::groth16::Parameters<_> = {
        let empty_circuit = MyZKSecretNumberCircuit::<Scalar> {
            secret_number: None,
            threshold: None,
        };
        generate_random_parameters::<Bls12, _, _>(empty_circuit, rng)
    }
    .expect("Secret Number must be a ZK circuit");
    params
}

// ZK circuit to prove the secret number is bigger than threshold
impl<F: PrimeField> bellman::Circuit<F> for MyZKSecretNumberCircuit<F> {
    fn synthesize<CS: bellman::ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> core::result::Result<(), bellman::SynthesisError> {
        let secret_number = cs.alloc(
            || "secret_number",
            || {
                self.secret_number
                    .ok_or(bellman::SynthesisError::AssignmentMissing)
            },
        )?;
        let threshold = cs.alloc(
            || "threshold",
            || {
                self.threshold
                    .ok_or(bellman::SynthesisError::AssignmentMissing)
            },
        )?;
        // CS::one().
        // let threshold = (self.threshold, CS::one());
        // enforce it's prime
        cs.enforce(
            || "grade above threshold",
            |lc| lc + secret_number,
            |lc| lc + CS::one(),
            |lc| lc + threshold,
        );

        Ok(())
    }
}
