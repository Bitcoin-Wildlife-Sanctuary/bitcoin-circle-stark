use crate::twiddle_merkle_tree::TwiddleMerkleTreeProof;
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
    pub fn verify_and_remove_proof() {}
}
