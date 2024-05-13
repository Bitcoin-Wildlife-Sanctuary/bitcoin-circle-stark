use crate::channel_commit::CommitmentGadget;
use crate::merkle_tree::MerkleTreeProof;
use bitvm::bigint::bits::limb_to_be_bits_toaltstack;
use bitvm::treepp::*;

pub struct MerkleTreeGadget;

impl MerkleTreeGadget {
    pub fn push_merkle_tree_proof(merkle_proof: &MerkleTreeProof) -> Script {
        script! {
            { merkle_proof.leaf }
            for elem in merkle_proof.siblings.iter() {
                { elem.to_vec() }
            }
        }
    }

    pub(crate) fn query_and_verify_internal(logn: usize, is_sibling: bool) -> Script {
        script! {
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DEPTH OP_1SUB OP_ROLL

            // copy-paste the 4 elements
            //     ABCD -> CDAB -> CDABAB -> ABABCD-> ABABCDCD
            //  -> ABCDCDAB -> ABCDABCD

            OP_2SWAP
            OP_2DUP
            OP_2ROT
            OP_2DUP
            OP_2ROT
            OP_2SWAP

            { CommitmentGadget::commit_qm31() }

            if is_sibling {
                OP_DEPTH OP_1SUB OP_ROLL
                OP_FROMALTSTACK OP_NOTIF OP_SWAP OP_ENDIF
                OP_CAT OP_SHA256

                for _ in 1..logn {
                    OP_DEPTH OP_1SUB OP_ROLL
                    OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF
                    OP_CAT OP_SHA256
                }
            } else {
                for _ in 0..logn {
                    OP_DEPTH OP_1SUB OP_ROLL
                    OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF
                    OP_CAT OP_SHA256
                }
            }

            5 OP_ROLL
            OP_EQUALVERIFY
        }
    }

    /// input:
    ///   root_hash
    ///   pos
    ///
    /// output:
    ///   v (qm31 -- 4 elements)
    pub fn query_and_verify(logn: usize) -> Script {
        script! {
            { limb_to_be_bits_toaltstack(logn as u32) }
            { Self::query_and_verify_internal(logn, false) }
        }
    }

    pub fn query_and_verify_sibling(logn: usize) -> Script {
        script! {
            { limb_to_be_bits_toaltstack(logn as u32) }
            { Self::query_and_verify_internal(logn, true) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::math::{CM31, M31, QM31};
    use crate::merkle_tree::{MerkleTree, MerkleTreeGadget};
    use bitvm::treepp::*;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_u31_or_u30::{u31ext_equalverify, QM31 as QM31Gadget};

    #[test]
    fn test_merkle_tree_verify() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = MerkleTreeGadget::query_and_verify(logn);
            println!("MT.verify(2^{}) = {} bytes", logn, verify_script.len());

            let mut last_layer = vec![];
            for _ in 0..(1 << logn) {
                last_layer.push(QM31(
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                ));
            }

            let merkle_tree = MerkleTree::new(last_layer.clone());

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;

            let proof = merkle_tree.query(pos as usize);

            let script = script! {
                { MerkleTreeGadget::push_merkle_tree_proof(&proof) }
                { merkle_tree.root_hash.to_vec() }
                { pos }
                { verify_script.clone() }
                { last_layer[pos as usize] }
                { u31ext_equalverify::<QM31Gadget>() }
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_merkle_tree_verify_sibling() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = MerkleTreeGadget::query_and_verify_sibling(logn);

            let mut last_layer = vec![];
            for _ in 0..(1 << logn) {
                last_layer.push(QM31(
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                ));
            }

            let merkle_tree = MerkleTree::new(last_layer.clone());

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;

            let proof = merkle_tree.query((pos ^ 1) as usize);

            let script = script! {
                { MerkleTreeGadget::push_merkle_tree_proof(&proof) }
                { merkle_tree.root_hash.to_vec() }
                { pos }
                { verify_script.clone() }
                { last_layer[(pos ^ 1) as usize] }
                { u31ext_equalverify::<QM31Gadget>() }
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
