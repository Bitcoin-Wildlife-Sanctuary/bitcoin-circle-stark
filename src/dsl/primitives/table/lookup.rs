use crate::treepp::*;

pub struct Lookup8BitGadget;

impl Lookup8BitGadget {
    /// Lookup the product of two 8-bits elements
    ///
    /// Input:
    /// - table
    /// - (k elements)
    /// - a
    /// - b
    ///
    /// Output:
    /// - table
    /// - (k elements)
    /// - a * b
    pub fn lookup(k: usize) -> Script {
        script! {
            // compute a + b and put it in the altstack
            OP_2DUP
            OP_ADD
            OP_TOALTSTACK

            // compare abs(a - b)
            OP_SUB
            OP_ABS

            // obtain the element for abs(a - b)
            if k != 0 {
                { k }
                OP_ADD
            }
            OP_PICK

            // stack: result related to abs(a - b)
            // altstack: a + b

            OP_FROMALTSTACK
            OP_SWAP OP_TOALTSTACK

            if k != 0 {
                { k }
                OP_ADD
            }
            OP_PICK

            OP_FROMALTSTACK
            OP_SUB
        }
    }
}

#[cfg(test)]
mod test {
    use crate::dsl::primitives::table::get_table;
    use crate::dsl::primitives::table::lookup::Lookup8BitGadget;
    use crate::treepp::*;
    use bitcoin_script::script;
    use bitcoin_scriptexec::execute_script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_lookup_8bit() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let table = get_table();

        for i in 0..100 {
            let a = prng.gen_range(0usize..(1 << 8));
            let b = prng.gen_range(0usize..(1 << 8));

            let expected = a * b;

            let script = script! {
                { table }
                for _ in 0..i {
                    { 1 }
                }
                { a }
                { b }
                { Lookup8BitGadget::lookup(i) }
                { expected }
                OP_EQUALVERIFY
                for _ in 0..i {
                    OP_DROP
                }
                for _ in 0..256 {
                    OP_2DROP
                }
                OP_DROP
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
