use crate::treepp::*;
use crate::utils::{
    dup_m31_vec_gadget, hash, hash_m31_vec_gadget, limb_to_be_bits_toaltstack_except_lowest_1bit,
    m31_vec_from_bottom_gadget,
};
use crate::OP_HINT;

/// Gadget for verifying a regular binary Merkle tree.
pub struct MerkleTreeTwinGadget;

impl MerkleTreeTwinGadget {
    pub(crate) fn query_and_verify_internal(len: usize, logn: usize) -> Script {
        script! {
            // left
            { m31_vec_from_bottom_gadget(len) }

            // duplicate the left
            { dup_m31_vec_gadget(len) }

            // hash the left and keep the hash in the altstack
            { hash_m31_vec_gadget(len) }
            hash
            OP_TOALTSTACK

            // right
            { m31_vec_from_bottom_gadget(len) }

            // duplicate the right
            { dup_m31_vec_gadget(len) }

            // hash the right
            { hash_m31_vec_gadget(len) }
            hash

            // put the left hash out and merge into the parent hash
            OP_FROMALTSTACK
            OP_SWAP OP_CAT hash

            { MerkleTreePathGadget::verify(logn - 1) }
        }
    }

    /// Query and verify using the Merkle path as a hint.
    ///
    /// Hint:
    /// - Merkle path
    ///
    /// Input:
    /// - root_hash
    /// - pos
    ///
    /// Output:
    /// - vl (the element on the left)
    /// - vr (the element on the right)
    pub fn query_and_verify(len: usize, logn: usize) -> Script {
        script! {
            // push the root hash to the altstack, first
            OP_SWAP OP_TOALTSTACK
            { limb_to_be_bits_toaltstack_except_lowest_1bit(logn as u32) }
            { Self::query_and_verify_internal(len, logn) }
        }
    }
}

/// Gadget that handles the path verification (non-leaf-related parts).
pub struct MerkleTreePathGadget;

impl MerkleTreePathGadget {
    /// Verify the Merkle tree path.
    ///
    /// Hint:
    /// - `path_len` sibling elements.
    ///
    /// Input:
    /// - starting hash
    ///
    /// Input from altstack:
    /// - root hash
    /// - control bits
    ///
    /// Output: none
    ///
    /// It fails the script execution if the root hash doesn't match.
    pub fn verify(path_len: usize) -> Script {
        script! {
            for _ in 0..path_len {
                OP_HINT
                OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF
                OP_CAT hash
            }

            OP_FROMALTSTACK
            OP_EQUALVERIFY
        }
    }
}

#[cfg(test)]
mod test {
    use crate::merkle_tree::bitcoin_script::MerkleTreeTwinGadget;
    use crate::merkle_tree::MerkleTreeTwinProof;
    use crate::treepp::*;
    use crate::utils::get_rand_qm31;
    use crate::{merkle_tree::MerkleTree, tests_utils::report::report_bitcoin_script_size};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_merkle_tree_verify() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = MerkleTreeTwinGadget::query_and_verify(4, logn);

            report_bitcoin_script_size(
                "MerkleTreeTwin",
                format!("verify(2^{})", logn).as_str(),
                verify_script.len(),
            );

            let mut last_layer = vec![];
            for _ in 0..(1 << logn) {
                let a = get_rand_qm31(&mut prng);
                last_layer.push(a.to_m31_array().to_vec());
            }

            let merkle_tree = MerkleTree::new(last_layer.clone());

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;
            if pos % 2 == 1 {
                pos -= 1;
            }

            let proof = MerkleTreeTwinProof::query(&merkle_tree, pos as usize);
            assert!(proof.verify(&merkle_tree.root_hash, logn, pos as usize));

            let script = script! {
                { proof }
                { merkle_tree.root_hash }
                { pos }
                { verify_script.clone() }
                for elem in last_layer[(pos | 1) as usize].iter().rev() {
                    { *elem }
                    OP_EQUALVERIFY
                }
                for elem in last_layer[pos as usize].iter().rev() {
                    { *elem }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
