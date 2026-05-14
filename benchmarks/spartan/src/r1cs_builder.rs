// Builds a constraint-count-matched synthetic R1CS using Spartan's built-in generator.
//
// ECDSA base constraints: 300_000 (matches gnark empirical from Table V).
// Poseidon per Merkle level: 240 constraints.
// Total for depth d: 300_000 + 240*d.
//
// We use Instance::produce_synthetic_r1cs which generates a fully satisfiable R1CS
// of the requested size. The paper notes this is a synthetic circuit matched on
// constraint count; the curve is curve25519/Ristretto, not BN254.

use libspartan::{Instance, VarsAssignment, InputsAssignment};

const ECDSA_CONSTRAINTS: usize = 300_000;
const POSEIDON_PER_LEVEL: usize = 240;

pub fn constraint_count(depth: usize) -> usize {
    ECDSA_CONSTRAINTS + POSEIDON_PER_LEVEL * depth
}

pub fn build_synthetic(depth: usize) -> (Instance, VarsAssignment, InputsAssignment, usize, usize) {
    let target = constraint_count(depth);
    // Spartan requires num_cons and num_vars to each be an exact power of 2.
    let num_cons = target.next_power_of_two();
    let num_vars = num_cons;
    let num_inputs = 1usize;

    let (inst, vars, inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);
    (inst, vars, inputs, target, num_cons)  // return target (logical) and padded (actual)
}
