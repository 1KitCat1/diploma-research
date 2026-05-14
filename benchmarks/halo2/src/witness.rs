// Off-circuit witness generation using halo2curves secp256k1 arithmetic.

use ff::Field;
use halo2_base::{
    halo2_proofs::{
        arithmetic::CurveAffine,
        halo2curves::secp256k1::{Fq, Secp256k1Affine},
    },
    utils::{biguint_to_fe, fe_to_biguint, modulus},
};
use rand::{rngs::StdRng, SeedableRng};

use crate::circuit::MembershipInput;

pub fn generate(depth: usize, seed: u64) -> MembershipInput {
    let mut rng = StdRng::seed_from_u64(seed);

    // Random private key and message hash
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(&mut rng);
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msghash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(&mut rng);

    // Compute (r, s) following ECDSA math
    let k_nonce = <Secp256k1Affine as CurveAffine>::ScalarExt::random(&mut rng);
    let k_inv = k_nonce.invert().unwrap();
    let r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k_nonce)
        .coordinates()
        .unwrap();
    let x = r_point.x();
    let x_bigint = fe_to_biguint(x);
    let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
    let s = k_inv * (msghash + (r * sk));

    // Merkle siblings: simple field elements for each tree level
    let merkle_siblings: Vec<u64> = (0..depth).map(|i| i as u64 + 1).collect();

    MembershipInput { r, s, msghash, pk, merkle_siblings }
}
