// RISC Zero host: generates real ECDSA witnesses, builds proofs, measures metrics.
//
// Usage:
//   cargo run --release --bin bench -- --depths 10,15,20,25,32 --out risc0_results.csv
//
// Output CSV columns:
//   depth, cycles, prove_ms, verify_ms, proof_bytes, journal_bytes

use std::time::Instant;
use clap::Parser;
use k256::ecdsa::{SigningKey, Signature, signature::Signer};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use serde::Deserialize;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "10,15,20,25,32")]
    depths: String,
    #[arg(long, default_value = "risc0_results.csv")]
    out: String,
}

#[derive(serde::Serialize, Deserialize)]
struct GuestInput {
    msg_hash: [u8; 32],
    sig_r: [u8; 32],
    sig_s: [u8; 32],
    pubkey_compressed: [u8; 33],
    merkle_path: Vec<([u8; 32], bool)>,
}

/// Build a minimal Merkle tree of the given depth.
/// Returns (root, path_for_leaf_0).
fn build_merkle_tree(leaf_hash: [u8; 32], depth: usize) -> ([u8; 32], Vec<([u8; 32], bool)>) {
    // All sibling nodes are zero hashes (minimal tree — only leaf 0 is real).
    let zero_hash = [0u8; 32];
    let mut path = Vec::with_capacity(depth);
    let mut current = leaf_hash;

    for _ in 0..depth {
        let sibling = zero_hash;
        // leaf 0 is always the left child at every level
        let is_right_sibling = true;
        let mut hasher = Sha256::new();
        hasher.update(&current);
        hasher.update(&sibling);
        let parent: [u8; 32] = hasher.finalize().into();
        path.push((sibling, is_right_sibling));
        current = parent;
    }

    (current, path)
}

fn run_depth(depth: usize) -> anyhow::Result<CsvRow> {
    // --- Witness generation ---
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let msg = b"benchmark message for ECDSA membership proof";
    let msg_hash: [u8; 32] = Sha256::digest(msg).into();

    let sig: Signature = signing_key.sign(&msg_hash);
    let sig_bytes = sig.to_bytes();
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&sig_bytes[..32]);
    sig_s.copy_from_slice(&sig_bytes[32..]);

    let pubkey_compressed: [u8; 33] = verifying_key
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed pubkey is 33 bytes");

    let leaf_hash: [u8; 32] = Sha256::digest(&pubkey_compressed).into();
    let (_root, merkle_path) = build_merkle_tree(leaf_hash, depth);

    let input = GuestInput { msg_hash, sig_r, sig_s, pubkey_compressed, merkle_path };

    // --- Prove ---
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&input)?
        .build()?;

    let prover = risc0_zkvm::default_prover();
    let prove_start = Instant::now();
    let receipt = prover.prove(env, membership_methods::MEMBERSHIP_GUEST_ELF)?;
    let prove_ms = prove_start.elapsed().as_millis() as u64;

    // --- Metrics ---
    let stats = receipt.stats();
    let cycles = stats.total_cycles;

    let proof_bytes = bincode::serialize(&receipt.inner)
        .map(|b| b.len())
        .unwrap_or(0);
    let journal_bytes = receipt.journal.bytes.len();

    // --- Verify ---
    let verify_start = Instant::now();
    receipt.verify(membership_methods::MEMBERSHIP_GUEST_ID)?;
    let verify_ms = verify_start.elapsed().as_millis() as u64;

    println!(
        "depth={:>2}  cycles={:>10}  prove={:>6}ms  verify={:>4}ms  proof={:>7}B",
        depth, cycles, prove_ms, verify_ms, proof_bytes
    );

    Ok(CsvRow { depth, cycles, prove_ms, verify_ms, proof_bytes, journal_bytes })
}

#[derive(serde::Serialize)]
struct CsvRow {
    depth: usize,
    cycles: u64,
    prove_ms: u64,
    verify_ms: u64,
    proof_bytes: usize,
    journal_bytes: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let depths: Vec<usize> = args.depths
        .split(',')
        .map(|s| s.trim().parse().expect("depth must be integer"))
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
