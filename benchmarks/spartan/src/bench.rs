// Spartan (Bulletproofs-style IPA) membership benchmark.
//
// Usage:
//   cargo run --release --bin bench -- --depths 10,15,20,25,32 --out spartan_results.csv
//
// Output CSV:
//   depth, num_constraints, num_vars, prove_ms, verify_ms, proof_bytes
//
// Notes:
// - Spartan uses curve25519/Ristretto; EVM gas is N/A.
// - No trusted setup (transparent IPA inner argument).
// - The R1CS is constraint-count-matched synthetic (see r1cs_builder.rs).

mod r1cs_builder;

use std::time::Instant;
use clap::Parser;
use merlin::Transcript;
use libspartan::{SNARKGens, SNARK};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "10,15,20,25,32")]
    depths: String,
    #[arg(long, default_value = "spartan_results.csv")]
    out: String,
}

#[derive(serde::Serialize)]
struct CsvRow {
    depth: usize,
    target_constraints: usize,   // logical count (300k ECDSA + 240*depth)
    padded_constraints: usize,   // next power of 2 (what Spartan actually proves)
    prove_ms: u64,
    verify_ms: u64,
    proof_bytes: usize,
}

fn run_depth(depth: usize) -> anyhow::Result<CsvRow> {
    let (inst, vars, inputs, target_cons, padded_cons) = r1cs_builder::build_synthetic(depth);
    let num_inputs = 1usize;

    println!(
        "depth={:>2}  logical={:>8}  padded={:>8}  setting up...",
        depth, target_cons, padded_cons
    );

    let gens = SNARKGens::new(padded_cons, padded_cons, num_inputs, padded_cons);

    // Encode: commit to the R1CS structure (circuit-specific, reusable across proofs)
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // Prove
    let prove_start = Instant::now();
    let mut prover_transcript = Transcript::new(b"membership-spartan");
    let proof = SNARK::prove(
        &inst,
        &comm,
        &decomm,
        vars,
        &inputs,
        &gens,
        &mut prover_transcript,
    );
    let prove_ms = prove_start.elapsed().as_millis() as u64;

    let proof_bytes = bincode::serialize(&proof)
        .map(|b| b.len())
        .unwrap_or(0);

    // Verify
    let verify_start = Instant::now();
    let mut verifier_transcript = Transcript::new(b"membership-spartan");
    let result = proof.verify(&comm, &inputs, &mut verifier_transcript, &gens);
    let verify_ms = verify_start.elapsed().as_millis() as u64;

    if let Err(e) = result {
        eprintln!("  WARNING: verification failed at depth {}: {:?}", depth, e);
    }

    println!(
        "depth={:>2}  prove={:>6}ms  verify={:>4}ms  proof={:>7}B",
        depth, prove_ms, verify_ms, proof_bytes
    );

    Ok(CsvRow { depth, target_constraints: target_cons, padded_constraints: padded_cons, prove_ms, verify_ms, proof_bytes })
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let depths: Vec<usize> = args.depths
        .split(',')
        .map(|s| s.trim().parse().expect("integer depth"))
        .collect();

    let mut wtr = csv::Writer::from_path(&args.out)?;
    for depth in depths {
        let row = run_depth(depth)?;
        wtr.serialize(&row)?;
        wtr.flush()?;
    }
    println!("Results written to {}", args.out);
    Ok(())
}
