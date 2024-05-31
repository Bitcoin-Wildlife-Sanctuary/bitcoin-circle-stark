mod bitcoin_script;

use crate::treepp::*;
pub use bitcoin_script::*;
use num_traits::Zero;
use std::cmp::min;
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

// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
// due to inability to reconcile the dependency issues between BitVM and stwo.
fn limb_to_be_bits_common(num_bits: u32) -> Script {
    let min_i = min(22, num_bits - 1);
    script! {
        OP_TOALTSTACK

        // Push the powers of 2 onto the stack
        // First, all powers of 2 that we can push as 3-byte numbers
        for i in 0..min_i  {
            { 2 << i }
        }
        // Then, we double powers of 2 to generate the 4-byte numbers
        for _ in min_i..num_bits - 1 {
            OP_DUP
            OP_DUP
            OP_ADD
        }

        OP_FROMALTSTACK

        for _ in 0..num_bits - 2 {
            OP_2DUP OP_LESSTHANOREQUAL
            OP_IF
                OP_SWAP OP_SUB 1
            OP_ELSE
                OP_NIP 0
            OP_ENDIF
            OP_TOALTSTACK
        }

        OP_2DUP OP_LESSTHANOREQUAL
        OP_IF
            OP_SWAP OP_SUB 1
        OP_ELSE
            OP_NIP 0
        OP_ENDIF
    }
}

// Convert a limb to low-endian bits
// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
// due to inability to reconcile the dependency issues between BitVM and stwo.
fn limb_to_le_bits_common(num_bits: u32) -> Script {
    let min_i = min(22, num_bits - 1);
    script! {
        // Push the powers of 2 onto the stack
        // First, all powers of 2 that we can push as 3-byte numbers
        for i in 0..min_i - 1  {
            { 2 << i } OP_TOALTSTACK
        }
        if num_bits - 1 > min_i {
            { 2 << (min_i - 1) } OP_DUP OP_TOALTSTACK

            // Then, we double powers of 2 to generate the 4-byte numbers
            for _ in min_i..num_bits - 2 {
                OP_DUP
                OP_ADD
                OP_DUP OP_TOALTSTACK
            }

            OP_DUP
            OP_ADD OP_TOALTSTACK
        } else {
            { 2 << (min_i - 1) } OP_TOALTSTACK
        }

        for _ in 0..num_bits - 2 {
            OP_FROMALTSTACK
            OP_2DUP OP_GREATERTHANOREQUAL
            OP_IF
                OP_SUB 1
            OP_ELSE
                OP_DROP 0
            OP_ENDIF
            OP_SWAP
        }

        OP_FROMALTSTACK
        OP_2DUP OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB 1
        OP_ELSE
            OP_DROP 0
        OP_ENDIF

        OP_SWAP
    }
}

/// Convert a limb to low-endian bits
/// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
/// due to inability to reconcile the dependency issues between BitVM and stwo.
pub fn limb_to_le_bits(num_bits: u32) -> Script {
    if num_bits >= 2 {
        script! {
            { limb_to_le_bits_common(num_bits) }
        }
    } else {
        script! {}
    }
}

/// Convert a limb to low-endian bits but store them in the altstack for now
/// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
/// due to inability to reconcile the dependency issues between BitVM and stwo.
pub fn limb_to_le_bits_toaltstack(num_bits: u32) -> Script {
    if num_bits >= 2 {
        script! {
            { limb_to_le_bits_common(num_bits) }
            for _ in 0..num_bits {
                OP_TOALTSTACK
            }
        }
    } else {
        script! {}
    }
}

/// Convert a limb to big-endian bits
/// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
/// due to inability to reconcile the dependency issues between BitVM and stwo.
pub fn limb_to_be_bits(num_bits: u32) -> Script {
    if num_bits >= 2 {
        script! {
            { limb_to_be_bits_common(num_bits) }
            for _ in 0..num_bits - 2 {
                OP_FROMALTSTACK
            }
        }
    } else {
        script! {}
    }
}

/// Convert a limb to big-endian bits but store them in the altstack for now
/// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
/// due to inability to reconcile the dependency issues between BitVM and stwo.
pub fn limb_to_be_bits_toaltstack(num_bits: u32) -> Script {
    if num_bits >= 2 {
        script! {
            { limb_to_be_bits_common(num_bits) }
            OP_TOALTSTACK
            OP_TOALTSTACK
        }
    } else {
        script! {
            OP_TOALTSTACK
        }
    }
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
