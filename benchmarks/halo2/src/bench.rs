// Halo2 membership benchmark.
//
// Usage:
//   cargo run --release --bin bench -- --depths 10,15,20,25,32 --out halo2_results.csv
//
// Output CSV:
//   depth, advice_cells, prove_ms, verify_ms, proof_bytes

mod circuit;
mod witness;

use std::time::Instant;
use clap::Parser;
use halo2_base::{
    gates::circuit::{BaseCircuitParams, CircuitBuilderStage},
    gates::circuit::builder::BaseCircuitBuilder,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{keygen_pk, keygen_vk, create_proof, verify_proof},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255,
            TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "10,15,20,25,32")]
    depths: String,
    #[arg(long, default_value = "halo2_results.csv")]
    out: String,
}

#[derive(serde::Serialize)]
struct CsvRow {
    depth: usize,
    advice_cells: usize,
    prove_ms: u64,
    verify_ms: u64,
    proof_bytes: usize,
}

fn initial_params() -> BaseCircuitParams {
    BaseCircuitParams {
        k: circuit::K,
        num_advice_per_phase: vec![4],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![1],
        lookup_bits: Some(circuit::LOOKUP_BITS),
        num_instance_columns: 1,
    }
}

fn run_depth(kzg_params: &ParamsKZG<Bn256>, depth: usize) -> anyhow::Result<CsvRow> {
    let input = witness::generate(depth, 42);

    // --- Keygen stage ---
    let mut keygen_builder = BaseCircuitBuilder::<Fr>::from_stage(CircuitBuilderStage::Keygen)
        .use_params(initial_params());
    {
        let range = keygen_builder.range_chip();
        let ctx = keygen_builder.main(0);
        let root = circuit::membership_circuit(ctx, &range, &input);
        drop(range);
        keygen_builder.assigned_instances[0].push(root);
    }
    let final_params = keygen_builder.calculate_params(Some(20));

    let advice_cells: usize = keygen_builder
        .statistics()
        .gate
        .total_advice_per_phase
        .iter()
        .sum();

    let vk = keygen_vk(kzg_params, &keygen_builder)?;
    let pk = keygen_pk(kzg_params, vk, &keygen_builder)?;

    // --- Prover stage ---
    let mut prover_builder = BaseCircuitBuilder::<Fr>::from_stage(CircuitBuilderStage::Prover)
        .use_params(final_params);
    let root_val = {
        let range = prover_builder.range_chip();
        let ctx = prover_builder.main(0);
        let root = circuit::membership_circuit(ctx, &range, &input);
        drop(range);
        prover_builder.assigned_instances[0].push(root);
        *root.value()
    };

    let instances: Vec<Vec<Fr>> = vec![vec![root_val]];
    let instance_refs: Vec<&[Fr]> = instances.iter().map(|v| v.as_slice()).collect();

    let prove_start = Instant::now();
    let rng = StdRng::seed_from_u64(0);
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<_>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(
        kzg_params, &pk, &[prover_builder],
        &[&instance_refs], rng, &mut transcript,
    )?;
    let proof = transcript.finalize();
    let prove_ms = prove_start.elapsed().as_millis() as u64;

    // --- Verify ---
    let verify_start = Instant::now();
    let mut tr = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(kzg_params);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        kzg_params.verifier_params(),
        pk.get_vk(),
        strategy,
        &[&instance_refs],
        &mut tr,
    )?;
    let verify_ms = verify_start.elapsed().as_millis() as u64;

    println!(
        "depth={:>2}  advice_cells={:>9}  prove={:>7}ms  verify={:>4}ms  proof={:>7}B",
        depth, advice_cells, prove_ms, verify_ms, proof.len()
    );

    Ok(CsvRow { depth, advice_cells, prove_ms, verify_ms, proof_bytes: proof.len() })
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let depths: Vec<usize> = args.depths
        .split(',')
        .map(|s| s.trim().parse().expect("integer"))
        .collect();

    let kzg_params = ParamsKZG::<Bn256>::setup(circuit::K as u32, StdRng::seed_from_u64(0));

    let mut wtr = csv::Writer::from_path(&args.out)?;
    for depth in depths {
        let row = run_depth(&kzg_params, depth)?;
        wtr.serialize(&row)?;
        wtr.flush()?;
    }
    println!("Results written to {}", args.out);
    Ok(())
}
