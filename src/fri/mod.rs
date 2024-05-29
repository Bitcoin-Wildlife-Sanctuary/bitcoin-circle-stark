use crate::channel::Channel;
use crate::channel_commit::Commitment;
use crate::math::fft::get_twiddles;
use crate::merkle_tree::{MerkleTree, MerkleTreeProof};
use crate::twiddle_merkle_tree::{TwiddleMerkleTree, TwiddleMerkleTreeProof};
use stwo_prover::core::fft::ibutterfly;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;

mod bitcoin_script;
pub use bitcoin_script::*;

/// A FRI proof.
#[derive(Clone, Debug)]
pub struct FriProof {
    commitments: Vec<Commitment>,
    last_layer: Vec<QM31>,
    leaves: Vec<QM31>,
    merkle_proofs: Vec<Vec<MerkleTreeProof>>,
    twiddle_merkle_proofs: Vec<TwiddleMerkleTreeProof>,
}

const N_QUERIES: usize = 5; // cannot change. hardcoded in the Channel implementation

/// Generate a FRI proof.
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

        let (alpha, _) = channel.draw_qm31();

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
    let mut merkle_proofs = Vec::with_capacity(N_QUERIES);
    let mut twiddle_merkle_proofs = Vec::with_capacity(N_QUERIES);

    let twiddle_merkle_tree = TwiddleMerkleTree::new(n_layers);

    for mut query in queries {
        leaves.push(layers[0][query]);
        twiddle_merkle_proofs.push(twiddle_merkle_tree.query(query));
        let mut layer_decommitments = Vec::with_capacity(n_layers);
        for tree in trees.iter() {
            layer_decommitments.push(tree.query(query ^ 1));
            query >>= 1;
        }
        merkle_proofs.push(layer_decommitments);
    }
    FriProof {
        commitments,
        last_layer,
        leaves,
        merkle_proofs,
        twiddle_merkle_proofs,
    }
}

/// Verify the FRI proof.
pub fn fri_verify(
    channel: &mut Channel,
    logn: usize,
    proof: FriProof,
    twiddle_merkle_tree_root: [u8; 32],
) {
    let n_layers = logn - 1;

    // Draw factors.
    let mut factors = Vec::with_capacity(n_layers);
    for c in proof.commitments.iter() {
        channel.absorb_commitment(c);
        factors.push(channel.draw_qm31().0);
    }
    // Last layer.
    proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));
    // Check it's of half degree.
    assert_eq!(proof.last_layer[0], proof.last_layer[1]);
    // Queries.
    let queries = channel.draw_5queries(logn).0.to_vec();
    // Decommit.
    for (mut query, ((mut leaf, merkle_proof), twiddle_merkle_tree_proof)) in
        queries.iter().copied().zip(
            proof
                .leaves
                .iter()
                .copied()
                .zip(proof.merkle_proofs.iter())
                .zip(proof.twiddle_merkle_proofs.iter()),
        )
    {
        assert!(TwiddleMerkleTree::verify(
            twiddle_merkle_tree_root,
            logn - 1,
            twiddle_merkle_tree_proof,
            query
        ));
        for (i, (eval_proof, &alpha)) in merkle_proof.iter().zip(factors.iter()).enumerate() {
            assert!(MerkleTree::verify(
                proof.commitments[i].0,
                logn - i,
                &merkle_proof[i],
                query ^ 1
            ));

            let sibling = eval_proof.leaf;

            let (mut f0, mut f1) = if query & 1 == 0 {
                (leaf, sibling)
            } else {
                (sibling, leaf)
            };

            ibutterfly(
                &mut f0,
                &mut f1,
                twiddle_merkle_tree_proof.elements[n_layers - 1 - i].into(),
            );

            leaf = f0 + alpha * f1;

            query >>= 1;
        }
        // Check against last layer
        assert_eq!(leaf, proof.last_layer[query]);
    }
}
