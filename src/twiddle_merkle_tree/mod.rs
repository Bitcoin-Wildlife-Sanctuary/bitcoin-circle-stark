use crate::math::fft::get_twiddles;
use crate::math::{Field, M31};
use crate::utils::num_to_bytes;
use sha2::{Digest, Sha256};

mod bitcoin_script;
pub use bitcoin_script::*;

mod constants;
pub use constants::*;

/// A twiddle Merkle tree.
pub struct TwiddleMerkleTree {
    /// The inverse of the twiddle factors.
    pub twiddles_inverse: Vec<Vec<M31>>,
    /// Layers, which are compressed through hashes of (left || twiddle factor || right).
    pub layers: Vec<Vec<[u8; 32]>>,
    /// Root hash.
    pub root_hash: [u8; 32],
}

impl TwiddleMerkleTree {
    /// Construct the twiddle Merkle tree.
    pub fn new(logn: usize) -> Self {
        let mut twiddles = get_twiddles(logn + 1).to_vec();

        twiddles
            .iter_mut()
            .for_each(|row| row.iter_mut().for_each(|cell| *cell = cell.inverse()));

        let mut layers = vec![];

        let mut leaf_hashes: Vec<[u8; 32]> = Vec::with_capacity(1 << logn);
        for i in 0..(1 << logn) {
            let mut bytes = [0u8; 32];
            let hash = {
                let mut sha256 = Sha256::new();
                Digest::update(&mut sha256, num_to_bytes(twiddles[0][i]));
                sha256.finalize()
            };
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
                Digest::update(&mut hasher, &v[0]);
                Digest::update(&mut hasher, num_to_bytes(twiddles[cur_parent_layer_idx][i]));
                Digest::update(&mut hasher, &v[1]);
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
                    Digest::update(&mut hasher, &v[0]);
                    if cur_parent_layer_idx != logn {
                        Digest::update(
                            &mut hasher,
                            num_to_bytes(twiddles[cur_parent_layer_idx][i]),
                        );
                    }
                    Digest::update(&mut hasher, &v[1]);
                    hash_result.copy_from_slice(hasher.finalize().as_slice());
                    hash_result
                })
                .collect::<Vec<[u8; 32]>>();
            layers.push(cur.clone());
        }

        Self {
            twiddles_inverse: twiddles,
            layers,
            root_hash: cur[0],
        }
    }

    /// Query the twiddle Merkle tree and generate a proof.
    pub fn query(&self, mut pos: usize) -> TwiddleMerkleTreeProof {
        let logn = self.layers.len();

        let mut elements = vec![];
        let mut siblings = Vec::with_capacity(logn);

        for i in 0..logn - 1 {
            pos >>= 1;

            elements.push(self.twiddles_inverse[i][pos]);
            siblings.push(self.layers[i][pos ^ 1]);
        }

        elements.reverse();

        TwiddleMerkleTreeProof { elements, siblings }
    }

    /// Verify a twiddle Merkle tree proof.
    pub fn verify(
        root_hash: [u8; 32],
        logn: usize,
        proof: &TwiddleMerkleTreeProof,
        mut query: usize,
    ) -> bool {
        assert_eq!(proof.elements.len(), logn);
        assert_eq!(proof.siblings.len(), logn);

        query >>= 1;

        let bytes = {
            let mut sha256 = Sha256::new();
            Digest::update(&mut sha256, num_to_bytes(proof.elements[logn - 1]));
            sha256.finalize().to_vec()
        };

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);

        for i in 0..logn {
            let (f0, f1) = if query & 1 == 0 {
                (hash, proof.siblings[i])
            } else {
                (proof.siblings[i], hash)
            };

            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, &f0);
            if i != logn - 1 {
                Digest::update(&mut hasher, num_to_bytes(proof.elements[logn - 2 - i]));
            }
            Digest::update(&mut hasher, &f1);
            hash.copy_from_slice(hasher.finalize().as_slice());

            query >>= 1;
        }

        hash == root_hash
    }
}

/// A Merkle path proof for twiddle tree.
#[derive(Debug, Clone)]
pub struct TwiddleMerkleTreeProof {
    /// Leaf and intermediate nodes, which totals to (logn -1) inverse twiddle factors.
    pub elements: Vec<M31>,
    /// Sibling elements (in hashes).
    pub siblings: Vec<[u8; 32]>,
}

#[cfg(test)]
mod test {
    use crate::twiddle_merkle_tree::TwiddleMerkleTree;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_twiddle_merkle_tree() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let twiddle_merkle_tree = TwiddleMerkleTree::new(20);

        for _ in 0..10 {
            let query = (prng.gen::<u32>() % (1 << 21)) as usize;

            let proof = twiddle_merkle_tree.query(query);
            assert!(TwiddleMerkleTree::verify(
                twiddle_merkle_tree.root_hash,
                20,
                &proof,
                query
            ));
        }
    }
}
