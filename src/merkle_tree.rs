use crate::cfri::fields::QM31;
use crate::channel_commit::{Commitment, CommitmentGadget};
use bitvm::bigint::bits::u30_to_bits_toaltstack;
use bitvm::treepp::*;
use sha2::{Digest, Sha256};

pub struct MerkleTree {
    pub leaf_layer: Vec<QM31>,
    pub intermediate_layers: Vec<Vec<[u8; 32]>>,
    pub root_hash: [u8; 32],
}

impl MerkleTree {
    pub fn new(leaf_layer: Vec<QM31>) -> Self {
        assert!(leaf_layer.len().is_power_of_two());

        let mut intermediate_layers = vec![];
        let mut cur = leaf_layer
            .chunks_exact(2)
            .map(|v| {
                let commit_1 = Commitment::commit_qm31(v[0]);
                let commit_2 = Commitment::commit_qm31(v[1]);

                let mut hash_result = [0u8; 32];

                let mut hasher = Sha256::new();
                Digest::update(&mut hasher, &commit_1.0);
                Digest::update(&mut hasher, &commit_2.0);
                hash_result.copy_from_slice(hasher.finalize().as_slice());
                hash_result
            })
            .collect::<Vec<[u8; 32]>>();
        intermediate_layers.push(cur.clone());

        while cur.len() > 1 {
            cur = cur
                .chunks_exact(2)
                .map(|v| {
                    let mut hash_result = [0u8; 32];
                    let mut hasher = Sha256::new();
                    Digest::update(&mut hasher, &v[0]);
                    Digest::update(&mut hasher, &v[1]);
                    hash_result.copy_from_slice(hasher.finalize().as_slice());
                    hash_result
                })
                .collect::<Vec<[u8; 32]>>();
            intermediate_layers.push(cur.clone());
        }

        Self {
            leaf_layer,
            intermediate_layers,
            root_hash: cur[0],
        }
    }

    pub fn query(&self, mut pos: usize) -> (QM31, MerkleTreePath) {
        let logn = self.intermediate_layers.len();

        let elem = self.leaf_layer[pos];

        let mut merkle_tree_path = MerkleTreePath::default();
        merkle_tree_path
            .0
            .push(Commitment::commit_qm31(self.leaf_layer[pos ^ 1]).0);

        for i in 0..(logn - 1) {
            pos >>= 1;
            merkle_tree_path
                .0
                .push(self.intermediate_layers[i][pos ^ 1]);
        }

        (elem, merkle_tree_path)
    }
}

pub struct MerkleTreeGadget;

impl MerkleTreeGadget {
    pub fn push_merkle_tree_path(merkle_path: &MerkleTreePath) -> Script {
        script! {
            for elem in merkle_path.0.iter() {
                { elem.to_vec() }
            }
        }
    }

    /// input:
    ///   root_hash
    ///   v (qm31 -- 4 elements)
    ///   pos
    pub fn verify(logn: usize) -> Script {
        script! {
            { u30_to_bits_toaltstack(logn as u32) }
            { CommitmentGadget::commit_qm31() }

            for _ in 0..logn {
                OP_DEPTH OP_1SUB OP_ROLL
                OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF
                OP_CAT OP_SHA256
            }

            OP_EQUALVERIFY
        }
    }
}

#[derive(Default)]
pub struct MerkleTreePath(pub Vec<[u8; 32]>);

#[cfg(test)]
mod test {
    use crate::cfri::fields::{CM31, M31, QM31};
    use crate::merkle_tree::{MerkleTree, MerkleTreeGadget};
    use bitvm::treepp::*;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_merkle_tree_verify() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = MerkleTreeGadget::verify(logn);
            println!("MT.verify(2^{}) = {} bytes", logn, verify_script.len());

            let mut last_layer = vec![];
            for _ in 0..(1 << logn) {
                last_layer.push(QM31(
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                    CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                ));
            }

            let merkle_tree = MerkleTree::new(last_layer);

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;

            let (v, path) = merkle_tree.query(pos as usize);

            let script = script! {
                { MerkleTreeGadget::push_merkle_tree_path(&path) }
                { merkle_tree.root_hash.to_vec() }
                { v.clone() }
                { pos }
                { verify_script.clone() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
