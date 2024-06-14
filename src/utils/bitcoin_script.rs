use crate::treepp::*;

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
    script! {
        OP_SHA256
        for _ in 1..len {
            OP_CAT OP_SHA256
        }
    }
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
            OP_DEPTH OP_1SUB OP_ROLL
        }
    }
}

#[cfg(test)]
mod test {
    use crate::treepp::*;
    use crate::utils::{dup_m31_vec_gadget, trim_m31, trim_m31_gadget};
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
                    { elem }
                }
                { dup_m31_vec_gadget(i) }
                for elem in v.iter().rev() {
                    { elem } OP_EQUALVERIFY
                }
                for elem in v.iter().rev() {
                    { elem } OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
            v.push(M31::reduce(prng.next_u64()));
        }
    }
}
