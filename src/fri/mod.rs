use crate::channel::{ChannelWithHint, DrawHints, Sha256Channel};
use crate::merkle_tree::{MerkleTree, MerkleTreeProof};
use crate::twiddle_merkle_tree::{TwiddleMerkleTree, TwiddleMerkleTreeProof};
use crate::utils::get_twiddles;
use stwo_prover::core::channel::Channel;
use stwo_prover::core::fft::ibutterfly;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;
use stwo_prover::core::prover::N_QUERIES;
use stwo_prover::core::queries::Queries;
use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hash;

mod bitcoin_script;
pub use bitcoin_script::*;

/// A trait for generating the queries with hints.
pub trait QueriesWithHint: Sized {
    /// Generate the queries and the corresponding hints.
    fn generate_with_hints(
        channel: &mut impl ChannelWithHint,
        log_domain_size: u32,
        n_queries: usize,
    ) -> (Self, DrawHints);
}

impl QueriesWithHint for Queries {
    fn generate_with_hints(
        channel: &mut impl ChannelWithHint,
        log_domain_size: u32,
        n_queries: usize,
    ) -> (Self, DrawHints) {
        let res = channel.draw_queries_and_hints(n_queries, log_domain_size as usize);
        (
            Self {
                positions: res.0.into_iter().collect(),
                log_domain_size,
            },
            res.1,
        )
    }
}

/// A FRI proof.
#[derive(Clone, Debug)]
pub struct FriProof {
    commitments: Vec<BWSSha256Hash>,
    last_layer: Vec<QM31>,
    leaves: Vec<QM31>,
    merkle_proofs: Vec<Vec<MerkleTreeProof>>,
    twiddle_merkle_proofs: Vec<TwiddleMerkleTreeProof>,
}

/// Generate a FRI proof.
pub fn fri_prove(channel: &mut Sha256Channel, evaluation: Vec<QM31>) -> FriProof {
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

        channel.mix_digest(tree.root_hash);
        commitments.push(tree.root_hash);

        trees.push(tree);

        let (alpha, _) = channel.draw_felt_and_hints();

        layer = layer
            .chunks_exact(2)
            .zip(layer_twiddles)
            .map(|(f, twid)| {
                let (mut f0, mut f1) = (f[0], f[1]);
                ibutterfly(&mut f0, &mut f1, twid.inverse());
                f0 + alpha * f1
            })
            .collect();
    }

    // Last layer.
    let last_layer = layer;
    channel.mix_felts(&last_layer);

    // Queries.
    let queries = channel.draw_queries_and_hints(N_QUERIES, logn).0.to_vec();

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
    channel: &mut Sha256Channel,
    logn: usize,
    proof: FriProof,
    twiddle_merkle_tree_root: [u8; 32],
) {
    let n_layers = logn - 1;

    // Draw factors.
    let mut factors = Vec::with_capacity(n_layers);
    for c in proof.commitments.iter() {
        channel.mix_digest(*c);
        factors.push(channel.draw_felt_and_hints().0);
    }
    // Last layer.
    channel.mix_felts(&proof.last_layer);
    // Check it's of half degree.
    assert_eq!(proof.last_layer[0], proof.last_layer[1]);
    // Queries.
    let queries = channel.draw_queries_and_hints(N_QUERIES, logn).0.to_vec();
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
                &proof.commitments[i],
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
                twiddle_merkle_tree_proof.elements[n_layers - 1 - i],
            );

            leaf = f0 + alpha * f1;

            query >>= 1;
        }
        // Check against last layer
        assert_eq!(leaf, proof.last_layer[query]);
    }
}
