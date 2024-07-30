use crate::treepp::*;
use crate::OP_HINT;
use bitcoin_scriptexec::{profiler_end, profiler_start};
use sha2::{Digest, Sha256};
use std::cmp::min;

/// Call the selected hash function.
pub fn hash() -> Script {
    script! {
        { profiler_start("op_sha256") } OP_SHA256 { profiler_end("op_sha256") }
    }
}

/// Gadget for trimming away a m31 element to keep only logn bits.
pub fn trim_m31_gadget(logn: usize) -> Script {
    if logn == 31 {
        script! {}
    } else {
        script! {
            OP_TOALTSTACK
            { 1 << logn }
            for _ in logn..(31 - 1) {
                OP_DUP OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            for _ in logn..31 {
                OP_SWAP
                OP_2DUP OP_GREATERTHANOREQUAL
                OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
            }
        }
    }
}

/// Convert the column representation back to the field element.
///
/// Input:
/// - a, b, c, d
///
/// Output:
/// - d, c, b, a
pub fn qm31_reverse() -> Script {
    script! {
        OP_SWAP
        OP_2SWAP
        OP_SWAP
    }
}

/// Copy some stack elements to the altstack, where the stack top is being inserted first.
pub fn copy_to_altstack_top_item_first_in_gadget(n: usize) -> Script {
    script! {
        if n > 0 {
            OP_DUP OP_TOALTSTACK
        }
        if n > 1 {
            OP_OVER OP_TOALTSTACK
        }
        for i in 2..n {
            { i } OP_PICK OP_TOALTSTACK
        }
    }
}

/// Gadget for hashing k m31 elements (in the case of qm31, k = 4) in the script.
pub fn hash_m31_vec_gadget(len: usize) -> Script {
    if len == 0 {
        script! {
            { Sha256::new().finalize().to_vec() }
        }
    } else {
        script! {
            hash
            for _ in 1..len {
                OP_CAT hash
            }
        }
    }
}

/// Gadget for hashing a qm31 element.
pub fn hash_qm31_gadget() -> Script {
    hash_m31_vec_gadget(4)
}

/// Gadget for duplicating multiple m31 elements.
pub fn dup_m31_vec_gadget(len: usize) -> Script {
    if len == 1 {
        script! {
            OP_DUP
        }
    } else if len == 2 {
        script! {
            OP_2DUP
        }
    } else if len == 4 {
        script! {
            // A B C D
            OP_2SWAP
            // C D A B
            OP_2DUP
            // C D A B A B
            OP_2ROT
            // A B A B C D
            OP_2DUP
            // A B A B C D C D
            OP_2ROT
            // A B C D C D A B
            OP_2SWAP
            // A B C D A B C D
        }
    } else {
        script! {
            for _ in 0..len {
                { len - 1 } OP_PICK
            }
        }
    }
}

/// Gadget for pulling a m31 vector of k elements into the stack.
pub fn m31_vec_from_bottom_gadget(len: usize) -> Script {
    script! {
        for _ in 0..len {
            OP_HINT
        }
    }
}

/// Clean the stack.
pub fn clean_stack(num: usize) -> Script {
    script! {
        for _ in 0..(num / 2) {
            OP_2DROP
        }
        if num % 2 == 1 {
            OP_DROP
        }
    }
}

/// Convert a limb to low-endian bits
/// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
/// due to inability to reconcile the dependency issues between BitVM and stwo.
pub fn limb_to_le_bits(num_bits: u32) -> Script {
    assert!(num_bits >= 2);
    let min_i = min(22, num_bits - 1);
    script! {
        // Push the powers of 2 onto the stack
        // First, all powers of 2 that we can push as 3-byte numbers
        for i in 0..min_i - 1  {
            { 2 << i } OP_TOALTSTACK
        }
        { 2 << (min_i - 1) }
        if num_bits - 1 > min_i {
            OP_DUP OP_TOALTSTACK

            // Then, we double powers of 2 to generate the 4-byte numbers
            for _ in min_i..num_bits - 2 {
                OP_DUP
                OP_ADD
                OP_DUP OP_TOALTSTACK
            }

            OP_DUP
            OP_ADD OP_TOALTSTACK
        } else {
            OP_TOALTSTACK
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

fn limb_to_be_bits_toaltstack_common(num_bits: u32) -> Script {
    assert!(num_bits >= 2);
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

/// Convert a limb to big-endian bits but store them in the altstack for now
/// except the lowest 1 bit.
/// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
/// due to inability to reconcile the dependency issues between BitVM and stwo.
pub fn limb_to_be_bits_toaltstack_except_lowest_1bit(num_bits: u32) -> Script {
    script! {
        { limb_to_be_bits_toaltstack_common(num_bits) }
        OP_TOALTSTACK OP_DROP
    }
}

/// Convert a limb to big-endian bits but store them in the altstack for now
/// except the lowest 1 bit.
/// Adapted from https://github.com/BitVM/BitVM/blob/main/src/bigint/bits.rs
/// due to inability to reconcile the dependency issues between BitVM and stwo.
pub fn limb_to_be_bits_toaltstack_except_lowest_2bits(num_bits: u32) -> Script {
    script! {
        { limb_to_be_bits_toaltstack_common(num_bits) }
        OP_DROP
        OP_DROP
    }
}

#[cfg(test)]
mod test {
    use crate::treepp::*;
    use crate::utils::{
        dup_m31_vec_gadget, get_rand_qm31, hash_m31_vec, hash_m31_vec_gadget, hash_qm31,
        hash_qm31_gadget, trim_m31, trim_m31_gadget,
    };
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_prover::core::fields::m31::M31;

    #[test]
    fn test_trim_m31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for i in 10..=31 {
            let trim_script = trim_m31_gadget(i);
            println!("M31.trim({}) = {} bytes", i, trim_script.len());

            let a = M31::reduce(prng.next_u64());
            let b = trim_m31(a.0, i);

            let script = script! {
                { a.0 }
                { trim_script }
                { b }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_copy_m31_vec() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut v = vec![];
        for i in 0..=20 {
            let script = script! {
                for elem in v.iter() {
                    { *elem }
                }
                { dup_m31_vec_gadget(i) }
                for elem in v.iter().rev() {
                    { *elem } OP_EQUALVERIFY
                }
                for elem in v.iter().rev() {
                    { *elem } OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
            v.push(M31::reduce(prng.next_u64()));
        }
    }

    #[test]
    fn test_hash_qm31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..=20 {
            let elem = get_rand_qm31(&mut prng);
            let hash = hash_qm31(&elem);

            let script = script! {
                { elem }
                hash_qm31_gadget
                { hash.to_vec() }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_hash_m31_vec() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut v = vec![];
        for i in 0..=20 {
            let hash = hash_m31_vec(&v);
            let script = script! {
                for elem in v.iter() {
                    { *elem }
                }
                { hash_m31_vec_gadget(i) }
                { hash.to_vec() }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
            v.push(M31::reduce(prng.next_u64()));
        }
    }
}
