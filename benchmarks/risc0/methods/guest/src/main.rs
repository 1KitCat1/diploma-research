// RISC Zero guest: runs inside the zkVM and constitutes the "circuit".
// Inputs arrive via risc0_zkvm::env::read(); outputs are committed with env::commit().
//
// What is proven:
//   1. Knowledge of a valid secp256k1 ECDSA signature on `msg_hash` under `pubkey`.
//   2. SHA-256(pubkey_bytes) is a leaf in a Merkle tree of the given `depth`.
//   3. Following the provided `path` of sibling hashes yields `merkle_root`.
//
// Public outputs (committed to the receipt journal):
//   - merkle_root: [u8; 32]
//   - msg_hash:    [u8; 32]
//
// Private inputs (never revealed):
//   - signature (r, s): two 32-byte big-endian scalars
//   - pubkey compressed: [u8; 33]
//   - merkle path: Vec<([u8; 32], bool)>  — (sibling_hash, is_right)

#![no_main]
risc0_zkvm::guest::entry!(main);

use k256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Sha256, Digest};

#[derive(serde::Deserialize)]
struct GuestInput {
    msg_hash: [u8; 32],
    sig_r: [u8; 32],
    sig_s: [u8; 32],
    pubkey_compressed: [u8; 33],
    merkle_path: Vec<([u8; 32], bool)>,  // (sibling, is_right_sibling)
}

pub fn main() {
    let input: GuestInput = risc0_zkvm::env::read();

    // 1. Reconstruct and verify the ECDSA signature.
    let verifying_key = VerifyingKey::from_sec1_bytes(&input.pubkey_compressed)
        .expect("invalid pubkey");

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&input.sig_r);
    sig_bytes[32..].copy_from_slice(&input.sig_s);
    let signature = Signature::from_bytes(&sig_bytes.into())
        .expect("invalid signature bytes");

    // k256 verifies over the raw 32-byte pre-hash (prehashed mode).
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    verifying_key.verify_prehash(&input.msg_hash, &signature)
        .expect("ECDSA signature verification failed");

    // 2. Compute the Merkle leaf: SHA-256 of the compressed public key.
    let mut leaf_hash: [u8; 32] = Sha256::digest(&input.pubkey_compressed).into();

    // 3. Walk the Merkle path toward the root.
    for (sibling, is_right_sibling) in &input.merkle_path {
        let mut hasher = Sha256::new();
        if *is_right_sibling {
            // sibling is to the right: current || sibling
            hasher.update(&leaf_hash);
            hasher.update(sibling);
        } else {
            // sibling is to the left: sibling || current
            hasher.update(sibling);
            hasher.update(&leaf_hash);
        }
        leaf_hash = hasher.finalize().into();
    }

    // 4. Commit public outputs to the journal.
    risc0_zkvm::env::commit(&leaf_hash);   // merkle_root
    risc0_zkvm::env::commit(&input.msg_hash);
}
