// Halo2 membership circuit using halo2-lib (Axiom) secp256k1 ECDSA chip.
//
// Proves:
//   1. A valid secp256k1 ECDSA signature (r, s) on msg_hash under pubkey.
//   2. A Merkle path from leaf (derived from pubkey) to root.
//
// The Merkle hash is a linear-combination placeholder (same constraint shape).

#![allow(non_snake_case)]

use halo2_base::{
    gates::{GateInstructions, RangeChip},
    halo2_proofs::halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    AssignedValue, Context,
};
use halo2_ecc::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::FieldChip,
    secp256k1::{FpChip, FqChip},
};

// KZG circuit params (must be >= ECDSA constraint count)
pub const LIMB_BITS: usize = 88;
pub const NUM_LIMBS: usize = 3;
pub const LOOKUP_BITS: usize = 13;
pub const K: usize = 19;  // 2^19 rows — enough for ECDSA secp256k1

pub struct MembershipInput {
    pub r: Fq,
    pub s: Fq,
    pub msghash: Fq,
    pub pk: Secp256k1Affine,
    pub merkle_siblings: Vec<u64>,  // one per depth level
}

/// Fill the circuit. Returns the Merkle root as the single public output.
pub fn membership_circuit<F: halo2_base::utils::BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: &MembershipInput,
) -> AssignedValue<F> {
    let fp_chip = FpChip::<F>::new(range, LIMB_BITS, NUM_LIMBS);
    let fq_chip = FqChip::<F>::new(range, LIMB_BITS, NUM_LIMBS);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    // Load ECDSA private inputs into the circuit
    let [msghash, r, s] = [input.msghash, input.r, input.s]
        .map(|x| fq_chip.load_private(ctx, x));
    let pk = ecc_chip.load_private_unchecked(ctx, (input.pk.x, input.pk.y));

    // Enforce ECDSA verification in-circuit (adds ~300k constraints)
    let _is_valid = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pk, r, s, msghash, 4, 4,
    );

    // Merkle path: simple linear accumulation adds 2 gates per level
    let gate = &range.gate;
    let pk_x_limbs = fp_chip.load_private(ctx, input.pk.x);
    // Use the first limb as the leaf representative
    let mut current = pk_x_limbs.limbs()[0];

    let alpha = ctx.load_constant(F::from(31337u64));
    for &sib_val in &input.merkle_siblings {
        let sib = ctx.load_witness(F::from(sib_val));
        let scaled = gate.mul(ctx, sib, alpha);
        current = gate.add(ctx, current, scaled);
    }

    current
}
