use bitcoin::opcodes::Ordinary::OP_TOALTSTACK;
use bitvm::treepp::*;

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

pub fn copy_to_altstack_top_item_last_in(n: usize) -> Script {
    script! {
        for i in 0..n {
            { n - 1 - i } OP_PICK OP_TOALTSTACK
        }
    }
}

#[cfg(test)]
mod test {
    use crate::math::M31;
    use crate::utils::{trim_m31, trim_m31_gadget};
    use bitvm::treepp::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

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
