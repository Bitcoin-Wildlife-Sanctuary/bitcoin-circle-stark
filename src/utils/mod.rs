mod bitcoin_script;

pub use bitcoin_script::*;
use rand::RngCore;
use sha2::{Digest, Sha256};
use stwo_prover::core::circle::CirclePointIndex;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

/// Convert a m31 element to its Bitcoin integer representation.
pub fn num_to_bytes(v: M31) -> Vec<u8> {
    let mut bytes = Vec::new();

    let mut v = v.0;
    while v > 0 {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }

    if bytes.last().is_some() && bytes.last().unwrap() & 0x80 != 0 {
        bytes.push(0);
    }

    bytes
}

/// Compute the bit reversed index.
pub fn bit_reverse_index(i: usize, log_size: usize) -> usize {
    if i == 0 {
        return 0;
    }
    i.reverse_bits() >> (usize::BITS as usize - log_size)
}

/// Compute the Bitcoin-friendly hash of a few M31 elements.
pub fn hash_m31_vec(v: &[M31]) -> [u8; 32] {
    let mut res = [0u8; 32];

    if v.is_empty() {
        let hasher = Sha256::new();
        res.copy_from_slice(hasher.finalize().as_slice());
    } else {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, num_to_bytes(v[v.len() - 1]));
        res.copy_from_slice(hasher.finalize().as_slice());

        for elem in v.iter().rev().skip(1) {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, num_to_bytes(*elem));
            Digest::update(&mut hasher, res);
            res.copy_from_slice(hasher.finalize().as_slice());
        }
    }

    res
}

/// Compute the Bitcoin-friendly hash of a single QM31 element.
pub fn hash_qm31(v: &QM31) -> [u8; 32] {
    hash_m31_vec(&[v.1 .1, v.1 .0, v.0 .1, v.0 .0])
}

/// Trim a m31 element to have only logn bits.
pub fn trim_m31(v: u32, logn: usize) -> u32 {
    v & ((1 << logn) - 1)
}

/// Compute all the twiddle factors.
pub fn get_twiddles(mut logn: usize) -> Vec<Vec<M31>> {
    let mut twiddles = Vec::with_capacity(logn);

    let mut p = CirclePointIndex::subgroup_gen(logn as u32 + 1).to_point();
    let mut step = CirclePointIndex::subgroup_gen(logn as u32 - 1).to_point();

    let mut layer = Vec::with_capacity(1 << logn);
    for i in 0..(1 << (logn - 1)) {
        layer.push((p + step.mul(bit_reverse_index(i, logn - 1) as u128)).y);
    }
    twiddles.push(layer);
    for _ in 0..(logn - 1) {
        logn -= 1;
        let mut layer = Vec::with_capacity(1 << logn);
        for i in 0..(1 << (logn - 1)) {
            layer.push((p + step.mul(bit_reverse_index(i, logn - 1) as u128)).x);
        }
        twiddles.push(layer);
        p = p.double();
        step = step.double();
    }

    twiddles
}

/// Get a random qm31 element.
pub fn get_rand_qm31<R: RngCore>(prng: &mut R) -> QM31 {
    QM31::from_m31(
        M31::reduce(prng.next_u64()),
        M31::reduce(prng.next_u64()),
        M31::reduce(prng.next_u64()),
        M31::reduce(prng.next_u64()),
    )
}
