mod bitcoin_script;
use crate::fields::{Field, M31, QM31};
pub use bitcoin_script::*;

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

pub fn bit_reverse_index(i: usize, log_size: usize) -> usize {
    if i == 0 {
        return 0;
    }
    i.reverse_bits() >> (usize::BITS as usize - log_size)
}

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

pub fn trim_m31(v: u32, logn: usize) -> u32 {
    v & ((1 << logn) - 1)
}
