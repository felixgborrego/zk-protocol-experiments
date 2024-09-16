use zk_protocol_experiments::zksnarks;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a Zero Konledge prove that I know a the root of a number (in this case I know the root of 4 is 2)
    let prove_token_base64 = zksnarks::prover::generate_prove_for_known_root_base64(4, 2)?;

    println!("ZK prove token: ----\n{prove_token_base64}\n----\n");

    let result = zksnarks::verifier::verify_know_root_base64_proof(&prove_token_base64);

    match result {
        Ok(_) => println!("Yes the ZK protocol prove the statement is correct"),
        Err(e) => println!("No, ZK statement is invalid: {e}"),
    }

    Ok(())
}
