use std::collections::{BTreeSet, HashMap};
use stwo_prover::core::fields::m31::{BaseField, M31};
use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hash;
use stwo_prover::core::vcs::bws_sha256_merkle::BWSSha256MerkleHasher;
use stwo_prover::core::vcs::ops::MerkleHasher;
use stwo_prover::core::vcs::prover::MerkleDecommitment;

mod bitcoin_script;
use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;

/// A Merkle tree.
pub struct MerkleTree {
    /// Leaf layers, consisting of m31 elements.
    pub leaf_layer: Vec<Vec<M31>>,
    /// Intermediate layers.
    pub intermediate_layers: Vec<Vec<BWSSha256Hash>>,
    /// Root hash.
    pub root_hash: BWSSha256Hash,
}

impl MerkleTree {
    /// Create a new Merkle tree.
    pub fn new(leaf_layer: Vec<Vec<M31>>) -> Self {
        assert!(leaf_layer.len().is_power_of_two());

        let mut intermediate_layers = vec![];
        let mut cur = leaf_layer
            .chunks_exact(2)
            .map(|v| {
                let commit_1 = BWSSha256MerkleHasher::hash_node(None, &v[0]);
                let commit_2 = BWSSha256MerkleHasher::hash_node(None, &v[1]);

                BWSSha256MerkleHasher::hash_node(Some((commit_1, commit_2)), &[])
            })
            .collect::<Vec<BWSSha256Hash>>();
        intermediate_layers.push(cur.clone());

        while cur.len() > 1 {
            cur = cur
                .chunks_exact(2)
                .map(|v| BWSSha256MerkleHasher::hash_node(Some((v[0], v[1])), &[]))
                .collect::<Vec<BWSSha256Hash>>();
            intermediate_layers.push(cur.clone());
        }

        Self {
            leaf_layer,
            intermediate_layers,
            root_hash: cur[0],
        }
    }

    /// Query the Merkle tree and generate a corresponding proof.
    pub fn query(&self, mut pos: usize) -> MerkleTreeTwinProof {
        let logn = self.intermediate_layers.len();
        assert_eq!(pos & 1, 0);

        let mut merkle_tree_proof = MerkleTreeTwinProof {
            left: self.leaf_layer[pos].clone(),
            right: self.leaf_layer[pos | 1].clone(),
            ..Default::default()
        };

        for i in 0..(logn - 1) {
            pos >>= 1;
            merkle_tree_proof
                .siblings
                .push(self.intermediate_layers[i][pos ^ 1]);
        }

        merkle_tree_proof
    }

    /// Verify a Merkle tree proof.
    pub fn verify_twin(
        root_hash: &BWSSha256Hash,
        logn: usize,
        proof: &MerkleTreeTwinProof,
        mut query: usize,
    ) -> bool {
        assert_eq!(proof.siblings.len(), logn - 1);
        assert_eq!(query & 1, 0);

        let left_hash = BWSSha256MerkleHasher::hash_node(None, &proof.left);
        let right_hash = BWSSha256MerkleHasher::hash_node(None, &proof.right);

        let mut leaf_hash = BWSSha256MerkleHasher::hash_node(Some((left_hash, right_hash)), &[]);
        query >>= 1;

        for i in 0..logn - 1 {
            let (f0, f1) = if query & 1 == 0 {
                (leaf_hash, proof.siblings[i])
            } else {
                (proof.siblings[i], leaf_hash)
            };

            leaf_hash = BWSSha256MerkleHasher::hash_node(Some((f0, f1)), &[]);
            query >>= 1;
        }

        leaf_hash == *root_hash
    }
}

/// A Merkle tree proof.
#[derive(Default, Clone, Debug)]
pub struct MerkleTreeTwinProof {
    /// Leaf as an M31 array.
    pub left: Vec<M31>,
    /// Leaf sibling as an M31 array.
    pub right: Vec<M31>,
    /// All the intermediate sibling nodes.
    pub siblings: Vec<BWSSha256Hash>,
}

impl Pushable for MerkleTreeTwinProof {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        (&self).bitcoin_script_push(builder)
    }
}

impl Pushable for &MerkleTreeTwinProof {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        for v in self.left.iter() {
            builder = v.bitcoin_script_push(builder);
        }
        for v in self.right.iter() {
            builder = v.bitcoin_script_push(builder);
        }
        for elem in self.siblings.iter() {
            builder = elem.bitcoin_script_push(builder);
        }
        builder
    }
}

impl MerkleTreeTwinProof {
    /// Convert a stwo Merkle proof into twin proofs for each pairs of queries.
    pub fn from_stwo_proof(
        logn: usize,
        queries_parents: &[usize],
        values: &[Vec<BaseField>],
        merkle_decommitment: &MerkleDecommitment<BWSSha256MerkleHasher>,
    ) -> Vec<Self> {
        // find out all the queried positions and sort them
        let mut queries = vec![];
        for &queries_parent in queries_parents.iter() {
            queries.push(queries_parent << 1);
            queries.push((queries_parent << 1) + 1);
        }
        queries.sort_unstable();
        queries.dedup();

        // get the number of columns
        let column_num = values.len();

        // create the new value map
        let mut queries_values_map = HashMap::new();
        for (idx, &query) in queries.iter().enumerate() {
            let mut v = vec![];
            for value in values.iter().take(column_num) {
                v.push(value[idx]);
            }
            queries_values_map.insert(query, v);
        }

        // require the column witness to be empty
        assert!(merkle_decommitment.column_witness.is_empty());

        // turn hash witness into an iterator
        let mut hash_iterator = merkle_decommitment.hash_witness.iter();

        // create the merkle partial tree
        let mut layers: Vec<HashMap<usize, BWSSha256Hash>> = vec![];

        // create the leaf layer
        let mut layer = HashMap::new();
        for (&query, value) in queries_values_map.iter() {
            layer.insert(query, BWSSha256MerkleHasher::hash_node(None, value));
        }
        layers.push(layer);

        let mut positions = queries_parents.to_vec();
        positions.sort_unstable();

        // create the intermediate layers
        for i in 0..(logn - 1) {
            let mut layer = HashMap::new();
            let mut parents = BTreeSet::new();

            for &position in positions.iter() {
                layer.insert(
                    position,
                    BWSSha256MerkleHasher::hash_node(
                        Some((
                            *layers[i].get(&(position << 1)).unwrap(),
                            *layers[i].get(&((position << 1) + 1)).unwrap(),
                        )),
                        &[],
                    ),
                );

                if !positions.contains(&(position ^ 1)) && !layer.contains_key(&(position ^ 1)) {
                    layer.insert(position ^ 1, *hash_iterator.next().unwrap());
                }
                parents.insert(position >> 1);
            }

            layers.push(layer);
            positions = parents.iter().copied().collect::<Vec<usize>>();
        }

        assert_eq!(hash_iterator.next(), None);

        // cheery-pick the Merkle tree paths to construct the deterministic proofs
        let mut res = vec![];
        for &queries_parent in queries_parents.iter() {
            let mut siblings = vec![];

            let mut cur = queries_parent;
            for layer in layers.iter().take(logn).skip(1) {
                siblings.push(*layer.get(&(cur ^ 1)).unwrap());
                cur >>= 1;
            }

            res.push(Self {
                left: queries_values_map
                    .get(&(queries_parent << 1))
                    .unwrap()
                    .clone(),
                right: queries_values_map
                    .get(&((queries_parent << 1) + 1))
                    .unwrap()
                    .clone(),
                siblings,
            });
        }
        res
    }
}

#[cfg(test)]
mod test {
    use crate::merkle_tree::{MerkleTree, MerkleTreeTwinProof};
    use crate::utils::get_rand_qm31;
    use itertools::Itertools;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::collections::BTreeMap;
    use stwo_prover::core::backend::CpuBackend;
    use stwo_prover::core::fields::m31::BaseField;
    use stwo_prover::core::vcs::bws_sha256_merkle::BWSSha256MerkleHasher;
    use stwo_prover::core::vcs::prover::MerkleProver;

    #[test]
    fn test_merkle_tree() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut last_layer = vec![];
        for _ in 0..1 << 12 {
            let a = get_rand_qm31(&mut prng);
            last_layer.push(a.to_m31_array().to_vec());
        }

        let merkle_tree = MerkleTree::new(last_layer.clone());

        for _ in 0..10 {
            let mut query = (prng.gen::<u32>() % (1 << 12)) as usize;
            if query & 1 != 0 {
                query ^= 1;
            }

            let proof = merkle_tree.query(query);
            assert!(MerkleTree::verify_twin(
                &merkle_tree.root_hash,
                12,
                &proof,
                query
            ));
        }
    }

    #[test]
    fn test_from_stwo_proof() {
        const LOG_SIZE: usize = 12;
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let mut polynomials = vec![];
            for _ in 0..4 {
                let mut polynomial = vec![];
                for _ in 0..(1 << LOG_SIZE) {
                    polynomial.push(BaseField::reduce(prng.next_u64()));
                }
                polynomials.push(polynomial);
            }

            let polynomials_ref = polynomials.iter().collect::<Vec<&Vec<BaseField>>>();

            let prover =
                MerkleProver::<CpuBackend, BWSSha256MerkleHasher>::commit(polynomials_ref.clone());

            let queries = (0..20)
                .map(|_| prng.gen::<usize>() % (1 << LOG_SIZE))
                .map(|x| x >> 1)
                .collect::<Vec<usize>>();

            let (values, decommitment) = prover.decommit(
                BTreeMap::from([(
                    LOG_SIZE as u32,
                    queries
                        .iter()
                        .sorted()
                        .dedup()
                        .flat_map(|&x| [x << 1, (x << 1) + 1])
                        .collect::<Vec<usize>>(),
                )]),
                polynomials_ref,
            );

            let proofs =
                MerkleTreeTwinProof::from_stwo_proof(LOG_SIZE, &queries, &values, &decommitment);
            for (&query, proof) in queries.iter().zip(proofs.iter()) {
                assert!(MerkleTree::verify_twin(
                    &prover.root(),
                    LOG_SIZE,
                    proof,
                    query << 1
                ));
            }
        }
    }
}
