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
pub fn copy_to_altstack_top_item_first_in(n: usize) -> Script {
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

/// Gadget for hashing a qm31 element in the script.
pub fn hash_felt_gadget() -> Script {
    script! {
        OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256
    }
}

#[cfg(test)]
mod test {
    use crate::treepp::*;
    use crate::utils::{trim_m31, trim_m31_gadget};
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
}
