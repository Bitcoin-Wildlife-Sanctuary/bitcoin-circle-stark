use crate::twiddle_merkle_tree::TwiddleMerkleTreeProof;
use bitvm::bigint::bits::limb_to_be_bits_toaltstack;
use bitvm::treepp::*;

pub struct TwiddleMerkleTreeGadget;

impl TwiddleMerkleTreeGadget {
    pub fn push_twiddle_merkle_tree_proof(
        twiddle_merkle_tree_proof: &TwiddleMerkleTreeProof,
    ) -> Script {
        script! {
            for elem in twiddle_merkle_tree_proof.leaf.iter() {
                { *elem }
            }
            for elem in twiddle_merkle_tree_proof.siblings.iter() {
                { elem.to_vec() }
            }
        }
    }

    /// input:
    ///   root_hash
    ///   pos
    ///
    /// output:
    ///   v (m31 -- [num_layer] elements)
    pub fn query_and_verify(logn: usize) -> Script {
        let num_layer = logn - 1;
        script! {
            for _ in 0..num_layer {
                OP_DEPTH OP_1SUB OP_ROLL
            }

            OP_DUP OP_TOALTSTACK

            for _ in 1..num_layer {
                OP_SHA256
                OP_OVER OP_TOALTSTACK
                OP_CAT
            }

            OP_SHA256

            OP_SWAP
            { limb_to_be_bits_toaltstack(num_layer as u32) }

             for _ in 0..num_layer {
                OP_DEPTH OP_1SUB OP_ROLL
                OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF
                OP_CAT OP_SHA256
            }

            OP_EQUALVERIFY

            for _ in 0..num_layer {
                OP_FROMALTSTACK
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::twiddle_merkle_tree::{TwiddleMerkleTree, TwiddleMerkleTreeGadget};
    use bitvm::treepp::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_twiddle_merkle_tree() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = TwiddleMerkleTreeGadget::query_and_verify(logn);
            println!("TMT.verify(2^{}) = {} bytes", logn, verify_script.len());

            let twiddle_merkle_tree = TwiddleMerkleTree::new(logn);

            let mut pos: u32 = prng.gen();
            pos &= (1 << (logn - 1)) - 1;

            let proof = twiddle_merkle_tree.query(pos as usize);

            let script = script! {
                { TwiddleMerkleTreeGadget::push_twiddle_merkle_tree_proof(&proof) }
                { twiddle_merkle_tree.root_hash.to_vec() }
                { pos }
                { verify_script.clone() }
                for i in 0..(logn - 1) {
                    { proof.leaf[(logn - 1) - 1 - i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
