use crate::channel::Channel;
use crate::channel_commit::Commitment;
use crate::math::fft::{get_twiddles, ibutterfly};
use crate::math::{Field, QM31};
use crate::merkle_tree::{MerkleTree, MerkleTreeProof};
use crate::twiddle_merkle_tree::{TwiddleMerkleTree, TwiddleMerkleTreeProof};

mod bitcoin_script;
pub use bitcoin_script::*;

#[derive(Clone, Debug)]
pub struct FriProof {
    commitments: Vec<Commitment>,
    last_layer: Vec<QM31>,
    leaves: Vec<QM31>,
    evaluations_decommitments: Vec<Vec<MerkleTreeProof>>,
    twiddle_decommitments: Vec<TwiddleMerkleTreeProof>,
}

const N_QUERIES: usize = 5; // cannot change. hardcoded in the Channel implementation

pub fn fri_prove(channel: &mut Channel, evaluation: Vec<QM31>) -> FriProof {
    let logn = evaluation.len().ilog2() as usize;
    let n_layers = logn - 1;
    let twiddles = get_twiddles(logn);

    let mut layers = Vec::with_capacity(n_layers);
    let mut trees = Vec::with_capacity(n_layers);
    let mut layer = evaluation;

    // Commit.
    let mut commitments = Vec::with_capacity(n_layers);
    for layer_twiddles in twiddles.iter().take(n_layers) {
        layers.push(layer.clone());

        let tree = MerkleTree::new(layer.clone());

        let commitment = Commitment(tree.root_hash);
        channel.absorb_commitment(&commitment);
        commitments.push(commitment);

        trees.push(tree);

        let (alpha, _) = channel.draw_element();

        layer = layer
            .chunks_exact(2)
            .zip(layer_twiddles)
            .map(|(f, twid)| {
                let (mut f0, mut f1) = (f[0], f[1]);
                ibutterfly(&mut f0, &mut f1, twid.inverse().into());
                f0 + alpha * f1
            })
            .collect();
    }

    // Last layer.
    let last_layer = layer;
    last_layer.iter().for_each(|v| channel.absorb_qm31(v));

    // Queries.
    let queries = channel.draw_5queries(logn).0.to_vec();

    // Decommit.
    let mut leaves = Vec::with_capacity(N_QUERIES);
    let mut evaluations_decommitments = Vec::with_capacity(n_layers);
    let mut twiddle_decommitments = Vec::with_capacity(N_QUERIES);

    let twiddle_merkle_tree = TwiddleMerkleTree::new(n_layers);

    for mut query in queries {
        leaves.push(layers[0][query]);
        twiddle_decommitments.push(twiddle_merkle_tree.query(query >> 1));
        let mut layer_decommitments = Vec::with_capacity(n_layers);
        for tree in trees.iter() {
            layer_decommitments.push(tree.query(query ^ 1));
            query >>= 1;
        }
        evaluations_decommitments.push(layer_decommitments);
    }
    FriProof {
        commitments,
        last_layer,
        leaves,
        evaluations_decommitments,
        twiddle_decommitments,
    }
}

pub fn fri_verify(channel: &mut Channel, logn: usize, proof: FriProof) {
    let n_layers = logn - 1;

    // Draw factors.
    let mut factors = Vec::with_capacity(n_layers);
    for c in proof.commitments.iter() {
        channel.absorb_commitment(c);
        factors.push(channel.draw_element().0);
    }
    // Last layer.
    proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));
    // Check it's of half degree.
    assert_eq!(proof.last_layer[0], proof.last_layer[1]);
    // Queries.
    let queries = channel.draw_5queries(logn).0.to_vec();
    // Decommit.
    for (mut query, ((mut leaf, evaluations_decommitments), twiddle_merkle_tree_proof)) in
        queries.iter().copied().zip(
            proof
                .leaves
                .iter()
                .copied()
                .zip(proof.evaluations_decommitments.iter())
                .zip(proof.twiddle_decommitments.iter()),
        )
    {
        for (i, (&ref eval_proof, &alpha)) in evaluations_decommitments
            .iter()
            .zip(factors.iter())
            .enumerate()
        {
            assert!(MerkleTree::verify(
                proof.commitments[i].0,
                logn - i,
                &evaluations_decommitments[i],
                query ^ 1
            ));

            let sibling = eval_proof.leaf;

            let (mut f0, mut f1) = if query & 1 == 0 {
                (leaf, sibling)
            } else {
                (sibling, leaf)
            };
            ibutterfly(&mut f0, &mut f1, twiddle_merkle_tree_proof.leaf[i].into());
            leaf = f0 + alpha * f1;
            query >>= 1;
        }
        // Check against last layer
        assert_eq!(leaf, proof.last_layer[query]);
    }
}
