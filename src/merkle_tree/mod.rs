use crate::treepp::pushable::{Builder, Pushable};
use std::collections::{BTreeSet, HashMap};
use stwo_prover::core::fields::m31::{BaseField, M31};
use stwo_prover::core::vcs::ops::MerkleHasher;
use stwo_prover::core::vcs::prover::MerkleDecommitment;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;

mod bitcoin_script;
pub use bitcoin_script::*;

/// A Merkle tree.
pub struct MerkleTree {
    /// Leaf layers, consisting of m31 elements.
    pub leaf_layer: Vec<Vec<M31>>,
    /// Intermediate layers.
    pub intermediate_layers: Vec<Vec<Sha256Hash>>,
    /// Root hash.
    pub root_hash: Sha256Hash,
}

impl MerkleTree {
    /// Create a new Merkle tree.
    pub fn new(leaf_layer: Vec<Vec<M31>>) -> Self {
        assert!(leaf_layer.len().is_power_of_two());

        let mut intermediate_layers = vec![];
        let mut cur = leaf_layer
            .chunks_exact(2)
            .map(|v| {
                let commit_1 = Sha256MerkleHasher::hash_node(None, &v[0]);
                let commit_2 = Sha256MerkleHasher::hash_node(None, &v[1]);

                Sha256MerkleHasher::hash_node(Some((commit_1, commit_2)), &[])
            })
            .collect::<Vec<Sha256Hash>>();
        intermediate_layers.push(cur.clone());

        while cur.len() > 1 {
            cur = cur
                .chunks_exact(2)
                .map(|v| Sha256MerkleHasher::hash_node(Some((v[0], v[1])), &[]))
                .collect::<Vec<Sha256Hash>>();
            intermediate_layers.push(cur.clone());
        }

        Self {
            leaf_layer,
            intermediate_layers,
            root_hash: cur[0],
        }
    }
}

#[derive(Default, Clone, Debug)]
/// An internal proof type that excludes the leaf (or leaves).
pub struct MerkleTreePath {
    /// All the intermediate sibling nodes.
    pub siblings: Vec<Sha256Hash>,
}

impl Pushable for MerkleTreePath {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        for elem in self.siblings.iter() {
            builder = elem.bitcoin_script_push(builder);
        }
        builder
    }
}

impl MerkleTreePath {
    /// Generate the Merkle tree path.
    pub fn query(tree: &MerkleTree, mut pos: usize) -> Self {
        let mut siblings = vec![];

        let num_layers = tree.intermediate_layers.len();
        for i in 0..num_layers - 1 {
            pos >>= 1;
            siblings.push(tree.intermediate_layers[i][pos ^ 1]);
        }

        Self { siblings }
    }

    /// Verify the Merkle tree path given the root hash, the considered depth, the leaf hash, and the query.
    pub fn verify(
        &self,
        root_hash: &Sha256Hash,
        depth: usize,
        mut leaf_hash: Sha256Hash,
        mut query: usize,
    ) -> bool {
        assert_eq!(self.siblings.len(), depth);

        for i in 0..depth {
            let (f0, f1) = if query & 1 == 0 {
                (leaf_hash, self.siblings[i])
            } else {
                (self.siblings[i], leaf_hash)
            };

            leaf_hash = Sha256MerkleHasher::hash_node(Some((f0, f1)), &[]);
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
    /// Remaining path.
    pub path: MerkleTreePath,
}

impl Pushable for MerkleTreeTwinProof {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        for v in self.left.iter() {
            builder = v.bitcoin_script_push(builder);
        }
        for v in self.right.iter() {
            builder = v.bitcoin_script_push(builder);
        }
        self.path.bitcoin_script_push(builder)
    }
}

impl MerkleTreeTwinProof {
    /// Query the Merkle tree and generate a corresponding proof.
    pub fn query(tree: &MerkleTree, pos: usize) -> MerkleTreeTwinProof {
        assert_eq!(pos & 1, 0);

        let left = tree.leaf_layer[pos].clone();
        let right = tree.leaf_layer[pos | 1].clone();
        let path = MerkleTreePath::query(tree, pos);

        MerkleTreeTwinProof { left, right, path }
    }

    /// Verify a Merkle tree proof.
    pub fn verify(&self, root_hash: &Sha256Hash, logn: usize, mut query: usize) -> bool {
        assert_eq!(query & 1, 0);

        let left_hash = Sha256MerkleHasher::hash_node(None, &self.left);
        let right_hash = Sha256MerkleHasher::hash_node(None, &self.right);

        let leaf_hash = Sha256MerkleHasher::hash_node(Some((left_hash, right_hash)), &[]);
        query >>= 1;

        self.path.verify(root_hash, logn - 1, leaf_hash, query)
    }

    /// Convert a stwo Merkle proof into twin proofs for each pairs of queries.
    pub fn from_stwo_proof(
        logn: usize,
        queries_parents: &[usize],
        values: &[Vec<BaseField>],
        merkle_decommitment: &MerkleDecommitment<Sha256MerkleHasher>,
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
        let mut layers: Vec<HashMap<usize, Sha256Hash>> = vec![];

        // create the leaf layer
        let mut layer = HashMap::new();
        for (&query, value) in queries_values_map.iter() {
            layer.insert(query, Sha256MerkleHasher::hash_node(None, value));
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
                    Sha256MerkleHasher::hash_node(
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
                path: MerkleTreePath { siblings },
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
    use stwo_prover::core::vcs::prover::MerkleProver;
    use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;

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

            let proof = MerkleTreeTwinProof::query(&merkle_tree, query);
            assert!(proof.verify(&merkle_tree.root_hash, 12, query));
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
                MerkleProver::<CpuBackend, Sha256MerkleHasher>::commit(polynomials_ref.clone());

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
                assert!(proof.verify(&prover.root(), LOG_SIZE, query << 1));
            }
        }
    }
}
