# Rust ZK Benchmarks

Three independent implementations of the same ECDSA + Merkle membership proof, one per proof system.

## Subdirectories

| Directory | Scheme | Proof type | Setup |
|-----------|--------|-----------|-------|
| `risc0/`  | zk-STARK | RISC Zero zkVM (STARK over RISC-V execution) | Transparent |
| `halo2/`  | Halo2 | PSE halo2 + Axiom halo2-lib, KZG | Trusted (unsafe bench) |
| `spartan/`| Bulletproofs | Spartan R1CS + IPA | Transparent |

## Prerequisites

### RISC Zero toolchain (required for `risc0/` only)
```bash
curl -L https://risczero.com/install | bash
rzup install
```
This installs the RISC-V target needed to compile guest code. Without it, the `risc0` crate will error at build time.

### Xcode (required for `risc0/` only on macOS)
RISC Zero builds Metal GPU shaders on macOS. Use the env var to skip them (CPU-only proving):
```bash
export RISC0_SKIP_BUILD_KERNELS=1
```
Or install full Xcode from the App Store for GPU-accelerated proving.

## Running

### RISC Zero (STARK)
```bash
cd risc0
cargo run --release --bin bench -- --depths 10,15,20,25,32 --out risc0_results.csv
```

### Halo2
```bash
cd halo2
cargo run --release --bin bench -- --depths 10,15,20,25,32 --out halo2_results.csv
```

### Spartan (Bulletproofs)
```bash
cd spartan
cargo run --release --bin bench -- --depths 10,15,20,25,32 --out spartan_results.csv
```

## Output columns

**risc0_results.csv:** `depth, cycles, prove_ms, verify_ms, proof_bytes, journal_bytes`

**halo2_results.csv:** `depth, advice_rows, prove_ms, verify_ms, proof_bytes`

**spartan_results.csv:** `depth, num_constraints, num_vars, prove_ms, verify_ms, proof_bytes`

## Notes

- RISC Zero measures CPU cycles (analogous to constraint count); proof size is ~200 KB for the default STARK.
- Halo2 `advice_rows` is the primary complexity metric; EVM gas from `snark-verifier` is not measured here.
- Spartan uses curve25519/Ristretto internally — no EVM verifier exists, so gas is N/A.
- The Spartan circuit is constraint-count-matched synthetic R1CS (see `spartan/src/r1cs_builder.rs`).
- All benchmarks use `--release` mode; run on the same machine as the gnark benchmarks for comparability.
