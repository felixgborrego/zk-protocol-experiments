// ZK Circuit to prove that prover know the root of a value x.
use bellman::{self, groth16::generate_random_parameters};
use bls12_381::{Bls12, Scalar};
use ff::PrimeField;
use rand::rngs::OsRng;

#[derive(Debug)]
pub struct SquereRootCircuit<F> {
    pub x: Option<F>,
    pub root: Option<F>,
}

impl<F: PrimeField> bellman::Circuit<F> for SquereRootCircuit<F> {
    fn synthesize<CS: bellman::ConstraintSystem<F>>(
        self,
        cs: &mut CS,
    ) -> Result<(), bellman::SynthesisError> {
        let x = cs.alloc(
            || "x",
            || self.x.ok_or(bellman::SynthesisError::AssignmentMissing),
        )?;
        let root = cs.alloc(
            || "root",
            || self.root.ok_or(bellman::SynthesisError::AssignmentMissing),
        )?;

        // root * root = x
        cs.enforce(|| "square", |lc| lc + root, |lc| lc + root, |lc| lc + x);
        Ok(())
    }
}

pub fn secret_root_init_params() -> bellman::groth16::Parameters<Bls12> {
    let rng = &mut OsRng;
    let params: bellman::groth16::Parameters<_> = {
        let empty_circuit = SquereRootCircuit::<Scalar> {
            x: None,
            root: None,
        };
        generate_random_parameters::<Bls12, _, _>(empty_circuit, rng)
    }
    .expect("Secret Number must be a ZK circuit");
    params
}
