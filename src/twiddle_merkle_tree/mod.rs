use crate::fft::get_twiddles;
use crate::fields::M31;
use crate::utils::num_to_bytes;
use sha2::{Digest, Sha256};

pub struct TwiddleMerkleTree {
    pub leaf_layer: Vec<Vec<M31>>,
    pub leaf_hashes: Vec<[u8; 32]>,
    pub intermediate_layers: Vec<Vec<[u8; 32]>>,
    pub root_hash: [u8; 32],
}

impl TwiddleMerkleTree {
    pub fn new(logn: usize) -> Self {
        let twiddles = get_twiddles(logn).to_vec();

        let mut leaf_layer: Vec<Vec<M31>> = Vec::with_capacity(1 << logn);
        let mut leaf_hashes: Vec<[u8; 32]> = Vec::with_capacity(1 << logn);

        for i in 0..1 << logn {
            let mut leaf = Vec::with_capacity(logn);

            let mut cur = i;
            for j in 0..logn {
                leaf.push(twiddles[j][cur ^ 1]);
                cur >>= 1;
            }

            let mut hash = {
                let mut sha256 = Sha256::new();
                Digest::update(&mut sha256, num_to_bytes(leaf[logn - 1]));
                sha256.finalize().to_vec()
            };

            for j in 1..logn {
                let mut sha256 = Sha256::new();
                Digest::update(&mut sha256, num_to_bytes(leaf[logn - 1 - j]));
                Digest::update(&mut sha256, &hash);
                hash = sha256.finalize().to_vec();
            }

            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hash);

            leaf_layer.push(leaf);
            leaf_hashes.push(bytes);
        }

        let mut intermediate_layers = vec![];
        let mut cur = leaf_hashes
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
            leaf_hashes,
            leaf_layer,
            intermediate_layers,
            root_hash: cur[0],
        }
    }

    pub fn query(&self, mut pos: usize) -> TwiddleMerkleTreePath {
        let logn = self.intermediate_layers.len();

        let leaf = self.leaf_layer[pos].clone();

        let mut siblings = Vec::with_capacity(logn);
        siblings.push(self.leaf_hashes[pos ^ 1]);

        for i in 0..(logn - 1) {
            pos >>= 1;
            siblings.push(self.intermediate_layers[i][pos ^ 1]);
        }

        TwiddleMerkleTreePath { leaf, siblings }
    }

    pub fn verify(
        root_hash: [u8; 32],
        num_layer: usize,
        path: &TwiddleMerkleTreePath,
        mut query: usize,
    ) -> bool {
        assert_eq!(path.leaf.len(), num_layer);
        assert_eq!(path.siblings.len(), num_layer);

        let logn = num_layer;

        let mut hash = {
            let mut sha256 = Sha256::new();
            Digest::update(&mut sha256, num_to_bytes(path.leaf[logn - 1]));
            sha256.finalize().to_vec()
        };

        for j in 1..logn {
            let mut sha256 = Sha256::new();
            Digest::update(&mut sha256, num_to_bytes(path.leaf[logn - 1 - j]));
            Digest::update(&mut sha256, &hash);
            hash = sha256.finalize().to_vec();
        }

        let mut leaf_hash = [0u8; 32];
        leaf_hash.copy_from_slice(&hash);

        for i in 0..num_layer {
            let (f0, f1) = if query & 1 == 0 {
                (leaf_hash, path.siblings[i])
            } else {
                (path.siblings[i], leaf_hash)
            };

            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, &f0);
            Digest::update(&mut hasher, &f1);
            leaf_hash.copy_from_slice(hasher.finalize().as_slice());

            query >>= 1;
        }

        leaf_hash == root_hash
    }
}

pub struct TwiddleMerkleTreePath {
    pub leaf: Vec<M31>,
    pub siblings: Vec<[u8; 32]>,
}
