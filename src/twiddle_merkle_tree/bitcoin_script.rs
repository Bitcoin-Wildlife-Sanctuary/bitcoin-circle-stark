use crate::treepp::*;
use crate::twiddle_merkle_tree::TwiddleMerkleTreeProof;
use crate::utils::limb_to_le_bits;

/// Gadget for verifying a Merkle tree path in a twiddle tree.
pub struct TwiddleMerkleTreeGadget;

impl TwiddleMerkleTreeGadget {
    /// Push a Merkle tree proof for the twiddle tree into the stack.
    pub fn push_twiddle_merkle_tree_proof(
        twiddle_merkle_tree_proof: &TwiddleMerkleTreeProof,
    ) -> Script {
        script! {
            { twiddle_merkle_tree_proof.elements.last().unwrap().clone() }
            for (element, sibling) in twiddle_merkle_tree_proof.elements.iter().rev().skip(1).zip(twiddle_merkle_tree_proof.siblings.iter()) {
                { *element }
                { sibling.to_vec() }
            }
            { twiddle_merkle_tree_proof.siblings.last().unwrap().to_vec() }
        }
    }

    /// Query the twiddle tree on a point and verify the Merkle tree proof (as a hint).
    ///
    /// hint:
    ///   merkle path consisting of entries of the form (mid-element, sibling)
    ///
    /// input:
    ///   root_hash
    ///   pos
    ///
    /// output:
    ///   v (m31 -- [num_layer] elements)
    pub fn query_and_verify(logn: usize) -> Script {
        let num_layer = logn - 1;
        script! {
            // convert pos into bits and drop the LSB
            { limb_to_le_bits(logn as u32) }
            OP_DROP

            // obtain the leaf element v
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DUP OP_TOALTSTACK

            // compute the current element's hash
            OP_SHA256

            // stack: root_hash, <bits>, leaf-hash
            // altstack: leaf

            // for every layer
            for _ in 0..num_layer - 1 {
                // pull the middle element and copy to the altstack
                OP_DEPTH OP_1SUB OP_ROLL
                OP_DUP OP_TOALTSTACK

                // stack: root_hash, <bits>, leaf-hash, middle-element
                // altstack: leaf, middle-element

                // pull the sibling
                OP_DEPTH OP_1SUB OP_ROLL

                // stack: root_hash, <bits>, leaf-hash, middle-element, sibling
                // altstack: leaf, middle-element

                // pull a bit
                3 OP_ROLL
                // check if we need to swap, and swap if needed
                OP_IF OP_SWAP OP_ROT OP_ENDIF

                OP_CAT OP_CAT
                OP_SHA256
            }

            // pull the sibling
            OP_DEPTH OP_1SUB OP_ROLL

            // stack: root_hash, <bit>, leaf-hash, sibling

            // pull a bit
            OP_ROT
            // check if we need to swap, and swap if needed
            OP_IF OP_SWAP OP_ENDIF
            OP_CAT
            OP_SHA256

            OP_EQUALVERIFY

            for _ in 0..num_layer {
                OP_FROMALTSTACK
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::treepp::*;
    use crate::twiddle_merkle_tree::{TwiddleMerkleTree, TwiddleMerkleTreeGadget};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_twiddle_merkle_tree() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = TwiddleMerkleTreeGadget::query_and_verify(logn);
            println!("TMT.verify(2^{}) = {} bytes", logn, verify_script.len());

            let n_layers = logn - 1;

            let twiddle_merkle_tree = TwiddleMerkleTree::new(n_layers);

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;

            let proof = twiddle_merkle_tree.query(pos as usize);

            let script = script! {
                { TwiddleMerkleTreeGadget::push_twiddle_merkle_tree_proof(&proof) }
                { twiddle_merkle_tree.root_hash.to_vec() }
                { pos }
                { verify_script.clone() }
                for i in 0..n_layers {
                    { proof.elements[n_layers - 1 - i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
