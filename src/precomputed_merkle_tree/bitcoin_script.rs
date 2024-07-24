use crate::treepp::*;
use crate::utils::{hash, limb_to_le_bits};
use crate::OP_HINT;

/// Gadget for verifying a Merkle tree path in a precomputed data tree.
pub struct PrecomputedMerkleTreeGadget;

impl PrecomputedMerkleTreeGadget {
    /// Query the twiddle tree on a point and verify the Merkle tree proof (as a hint).
    ///
    /// hint:
    ///   merkle tree proof
    ///
    /// input:
    ///   pos
    ///
    /// output:
    ///   v (m31 -- [num_layer] elements)
    ///   circle point (x, y; 2 elements)
    pub fn query_and_verify(root: [u8; 32], logn: usize) -> Script {
        let num_layer = logn - 1;
        script! {
            // convert pos into bits and drop the LSB
            { limb_to_le_bits(logn as u32) }
            OP_DROP

            // obtain the circle point x and y
            OP_HINT
            OP_DUP OP_TOALTSTACK
            OP_HINT
            OP_DUP OP_TOALTSTACK

            // obtain the leaf element v
            OP_HINT
            OP_DUP OP_TOALTSTACK

            // compute the current element's hash
            hash OP_CAT hash OP_CAT hash

            // stack: root_hash, <bits>, leaf-hash
            // altstack: leaf

            // for every layer
            for _ in 0..num_layer - 1 {
                // pull the middle element and copy to the altstack
                OP_HINT
                OP_DUP OP_TOALTSTACK

                // stack: root_hash, <bits>, leaf-hash, middle-element
                // altstack: leaf, middle-element

                // pull the sibling
                OP_HINT

                // stack: root_hash, <bits>, leaf-hash, middle-element, sibling
                // altstack: leaf, middle-element

                // pull a bit
                3 OP_ROLL
                // check if we need to swap, and swap if needed
                OP_IF OP_SWAP OP_ROT OP_ENDIF

                OP_CAT OP_CAT
                hash
            }

            // pull the sibling
            OP_HINT

            // stack: root_hash, <bit>, leaf-hash, sibling

            // pull a bit
            OP_ROT
            // check if we need to swap, and swap if needed
            OP_IF OP_SWAP OP_ENDIF
            OP_CAT
            hash

            { root.to_vec() }
            OP_EQUALVERIFY

            for _ in 0..num_layer {
                OP_FROMALTSTACK
            }
            OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP
        }
    }
}

#[cfg(test)]
mod test {
    use crate::precomputed_merkle_tree::{PrecomputedMerkleTree, PrecomputedMerkleTreeGadget};
    use crate::treepp::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_precomputed_merkle_tree() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let n_layers = logn - 1;
            let tree = PrecomputedMerkleTree::new(n_layers);

            let verify_script = PrecomputedMerkleTreeGadget::query_and_verify(tree.root_hash, logn);
            println!("PMT.verify(2^{}) = {} bytes", logn, verify_script.len());

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;

            let proof = tree.query(pos as usize);

            let script = script! {
                { proof.clone() }
                { pos }
                { verify_script.clone() }
                { proof.circle_point.y }
                OP_EQUALVERIFY
                { proof.circle_point.x }
                OP_EQUALVERIFY
                for i in 0..n_layers {
                    { proof.twiddles_elements[n_layers - 1 - i] }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
