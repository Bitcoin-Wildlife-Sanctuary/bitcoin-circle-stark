use crate::treepp::pushable::*;
use crate::utils::{bit_reverse_index, get_twiddles};
use crate::utils::{hash_m31_vec, num_to_bytes};
use sha2::{Digest, Sha256};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::FieldExpOps;
use stwo_prover::core::poly::circle::CanonicCoset;

mod constants;
pub use constants::*;

/// A precomputed data Merkle tree.
pub struct PrecomputedMerkleTree {
    /// The twin children's point coordinates (only keep the left child)
    pub twin_points: Vec<CirclePoint<M31>>,
    /// The inverse of the twiddle factors.
    pub twiddles_inverse: Vec<Vec<M31>>,
    /// Layers, which are compressed through hashes of (left || twiddle factor || right).
    pub layers: Vec<Vec<[u8; 32]>>,
    /// Root hash.
    pub root_hash: [u8; 32],
}

impl PrecomputedMerkleTree {
    /// Construct the precomputed data Merkle tree.
    pub fn new(logn: usize) -> Self {
        let mut domain_iter = CanonicCoset::new((logn + 1) as u32)
            .circle_domain()
            .half_coset
            .iter();

        let mut twin_points = vec![CirclePoint::zero(); 1 << logn];
        for i in 0..(1 << logn) {
            let point = domain_iter.next().unwrap();
            twin_points[bit_reverse_index(i, logn)] = point;
        }

        let mut twiddles = get_twiddles(logn + 1).to_vec();

        twiddles
            .iter_mut()
            .for_each(|row| row.iter_mut().for_each(|cell| *cell = cell.inverse()));

        let mut layers = vec![];

        let mut leaf_hashes: Vec<[u8; 32]> = Vec::with_capacity(1 << logn);
        for (twin_point, twiddle) in twin_points.iter().zip(twiddles[0].iter()) {
            let mut bytes = [0u8; 32];
            let hash = hash_m31_vec(&[twin_point.x, twin_point.y, *twiddle]);
            bytes.copy_from_slice(&hash);
            leaf_hashes.push(bytes);
        }
        layers.push(leaf_hashes.clone());

        let mut cur_parent_layer_idx = 1;

        let mut cur = leaf_hashes
            .chunks_exact(2)
            .enumerate()
            .map(|(i, v)| {
                let mut hash_result = [0u8; 32];

                let mut hasher = Sha256::new();
                Digest::update(&mut hasher, v[0]);
                Digest::update(&mut hasher, num_to_bytes(twiddles[cur_parent_layer_idx][i]));
                Digest::update(&mut hasher, v[1]);
                hash_result.copy_from_slice(hasher.finalize().as_slice());
                hash_result
            })
            .collect::<Vec<[u8; 32]>>();
        layers.push(cur.clone());

        while cur.len() > 1 {
            cur_parent_layer_idx += 1;

            cur = cur
                .chunks_exact(2)
                .enumerate()
                .map(|(i, v)| {
                    let mut hash_result = [0u8; 32];
                    let mut hasher = Sha256::new();
                    Digest::update(&mut hasher, v[0]);
                    if cur_parent_layer_idx != logn {
                        Digest::update(
                            &mut hasher,
                            num_to_bytes(twiddles[cur_parent_layer_idx][i]),
                        );
                    }
                    Digest::update(&mut hasher, v[1]);
                    hash_result.copy_from_slice(hasher.finalize().as_slice());
                    hash_result
                })
                .collect::<Vec<[u8; 32]>>();
            layers.push(cur.clone());
        }

        Self {
            twin_points,
            twiddles_inverse: twiddles,
            layers,
            root_hash: cur[0],
        }
    }

    /// Query the twiddle Merkle tree and generate a proof.
    pub fn query(&self, mut pos: usize) -> PrecomputedMerkleTreeProof {
        let logn = self.layers.len();

        let circle_point = self.twin_points[pos >> 1];

        let mut elements = vec![];
        let mut siblings = Vec::with_capacity(logn);

        for i in 0..logn - 1 {
            pos >>= 1;

            elements.push(self.twiddles_inverse[i][pos]);
            siblings.push(self.layers[i][pos ^ 1]);
        }

        elements.reverse();

        PrecomputedMerkleTreeProof {
            circle_point,
            twiddles_elements: elements,
            siblings,
        }
    }

    /// Verify a twiddle Merkle tree proof.
    pub fn verify(
        root_hash: [u8; 32],
        logn: usize,
        proof: &PrecomputedMerkleTreeProof,
        mut query: usize,
    ) -> bool {
        assert_eq!(proof.twiddles_elements.len(), logn);
        assert_eq!(proof.siblings.len(), logn);

        query >>= 1;

        let bytes = hash_m31_vec(&[
            proof.circle_point.x,
            proof.circle_point.y,
            proof.twiddles_elements[logn - 1],
        ]);

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);

        for i in 0..logn {
            let (f0, f1) = if query & 1 == 0 {
                (hash, proof.siblings[i])
            } else {
                (proof.siblings[i], hash)
            };

            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, f0);
            if i != logn - 1 {
                Digest::update(
                    &mut hasher,
                    num_to_bytes(proof.twiddles_elements[logn - 2 - i]),
                );
            }
            Digest::update(&mut hasher, f1);
            hash.copy_from_slice(hasher.finalize().as_slice());

            query >>= 1;
        }

        hash == root_hash
    }
}

/// A Merkle path proof for twiddle tree.
#[derive(Debug, Clone)]
pub struct PrecomputedMerkleTreeProof {
    /// Circle point.
    pub circle_point: CirclePoint<M31>,
    /// Leaf and intermediate nodes, which totals to (logn -1) inverse twiddle factors.
    pub twiddles_elements: Vec<M31>,
    /// Sibling elements (in hashes).
    pub siblings: Vec<[u8; 32]>,
}

impl Pushable for PrecomputedMerkleTreeProof {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self.circle_point.x.bitcoin_script_push(builder);
        builder = self.circle_point.y.bitcoin_script_push(builder);
        builder = self
            .twiddles_elements
            .last()
            .unwrap()
            .bitcoin_script_push(builder);
        for (element, sibling) in self
            .twiddles_elements
            .iter()
            .rev()
            .skip(1)
            .zip(self.siblings.iter())
        {
            builder = element.bitcoin_script_push(builder);
            builder = sibling.to_vec().bitcoin_script_push(builder);
        }
        self.siblings
            .last()
            .unwrap()
            .to_vec()
            .bitcoin_script_push(builder)
    }
}

#[cfg(test)]
mod test {
    use crate::precomputed_merkle_tree::PrecomputedMerkleTree;
    use crate::utils::bit_reverse_index;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::ops::Neg;
    use stwo_prover::core::poly::circle::CanonicCoset;

    #[test]
    fn test_precomputed_merkle_tree() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let precomputed_merkle_tree = PrecomputedMerkleTree::new(20);

        for _ in 0..10 {
            let query = (prng.gen::<u32>() % (1 << 21)) as usize;

            let proof = precomputed_merkle_tree.query(query);
            assert!(PrecomputedMerkleTree::verify(
                precomputed_merkle_tree.root_hash,
                20,
                &proof,
                query
            ));
        }
    }

    #[test]
    fn test_consistency() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let precomptued_merkle_tree = PrecomputedMerkleTree::new(20);

        let coset_index = prng.gen::<u32>() % (1 << 20);

        let expected_left = CanonicCoset::new(21)
            .circle_domain()
            .at(bit_reverse_index((coset_index << 1) as usize, 21));
        let expected_right = CanonicCoset::new(21)
            .circle_domain()
            .at(bit_reverse_index(((coset_index << 1) + 1) as usize, 21));

        let result = precomptued_merkle_tree.twin_points[coset_index as usize];
        assert_eq!(expected_left, result);
        assert_eq!(expected_right, result.neg());
        assert_eq!(expected_left, expected_right.neg());
    }
}
