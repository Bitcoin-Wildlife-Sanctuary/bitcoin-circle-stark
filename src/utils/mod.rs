mod bitcoin_script;

use crate::math::{Field, M31, QM31};
pub use bitcoin_script::*;

/// Convert a m31 element to its Bitcoin integer representation.
pub fn num_to_bytes(v: M31) -> Vec<u8> {
    let mut bytes = Vec::new();

    let mut v = v.0;
    while v > 0 {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }

    if bytes.last().is_some() {
        if bytes.last().unwrap() & 0x80 != 0 {
            bytes.push(0);
        }
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

/// Perform the bit reversal of the evaluations.
pub fn permute_eval(evaluation: Vec<QM31>) -> Vec<QM31> {
    let logn = evaluation.len().ilog2() as usize;
    let mut layer = vec![QM31::zero(); evaluation.len()];
    for i in 0..evaluation.len() / 2 {
        layer[bit_reverse_index(i, logn)] = evaluation[i * 2];
        layer[bit_reverse_index(i + evaluation.len() / 2, logn)] =
            evaluation[evaluation.len() - 1 - i * 2];
    }
    layer
}

/// Trim a m31 element to have only logn bits.
pub fn trim_m31(v: u32, logn: usize) -> u32 {
    v & ((1 << logn) - 1)
}
