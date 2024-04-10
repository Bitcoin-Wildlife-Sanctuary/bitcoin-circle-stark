use crate::cfri::{
    channel::{Channel, Commitment},
    fft::{get_twiddles, ibutterfly},
    fields::{Field, QM31},
};

// TODO: This should be a merkle commitment.
#[derive(Clone, Debug)]
pub struct FriProof {
    commitments: Vec<Commitment>,
    last_layer: Vec<QM31>,
    leaves: Vec<QM31>,
    siblings: Vec<Vec<QM31>>,
    pub decommitments: Vec<Vec<()>>,
}

const N_QUERIES: usize = 5;

pub fn fri_prove(channel: &mut Channel, evaluation: Vec<QM31>) -> FriProof {
    let logn = evaluation.len().ilog2() as usize;
    let n_layers = logn - 1;
    let twiddles = get_twiddles(logn);

    let mut layers = Vec::with_capacity(n_layers);
    let mut layer = evaluation;
    // Commit.
    let mut commitments = Vec::with_capacity(n_layers);
    for layer_twiddles in twiddles.iter().take(n_layers) {
        layers.push(layer.clone());
        // TODO: This should be a merkle commitment.
        let commitment = layer.clone();
        // TODO: Update channel with commitment hash instead.
        channel.mix_with_commitment(&commitment);
        commitments.push(commitment);

        let alpha = channel.draw_element();

        layer = layer
            .array_chunks()
            .zip(layer_twiddles)
            .map(|(&[f_x, f_neg_x], twid)| {
                let (mut f0, mut f1) = (f_x, f_neg_x);
                ibutterfly(&mut f0, &mut f1, twid.inverse().into());
                f0 + alpha * f1
            })
            .collect();
    }
    // Last layer.
    // TODO: Send only the coefficients.
    let last_layer = layer;
    last_layer.iter().for_each(|v| channel.mix_with_el(v));

    // Queries.
    let queries = (0..N_QUERIES)
        .map(|_| channel.draw_query(logn))
        .collect::<Vec<_>>();

    // Decommit.
    let mut leaves = Vec::with_capacity(N_QUERIES);
    let mut siblings = Vec::with_capacity(N_QUERIES);
    let mut decommitments = Vec::with_capacity(n_layers);
    for mut query in queries {
        leaves.push(layers[0][query]);
        let mut layer_sibling = Vec::with_capacity(n_layers);
        let mut layer_decommitments = Vec::with_capacity(n_layers);
        for layer in layers.iter() {
            layer_sibling.push(layer[query ^ 1]);
            // TODO: Add decommitment.
            layer_decommitments.push(());
            query >>= 1;
        }
        siblings.push(layer_sibling);
        decommitments.push(layer_decommitments);
    }
    FriProof {
        commitments,
        last_layer,
        leaves,
        siblings,
        decommitments,
    }
}

pub fn fri_verify(channel: &mut Channel, logn: usize, proof: FriProof) {
    let twiddles = get_twiddles(logn).to_vec();
    let n_layers = logn - 1;

    // Draw factors.
    let mut factors = Vec::with_capacity(n_layers);
    for c in proof.commitments.iter() {
        channel.mix_with_commitment(c);
        factors.push(channel.draw_element());
    }
    // Last layer.
    proof.last_layer.iter().for_each(|v| channel.mix_with_el(v));
    // Check it's of half degree.
    assert_eq!(proof.last_layer[0], proof.last_layer[1]);
    // Queries.
    let queries = (0..N_QUERIES)
        .map(|_| channel.draw_query(logn))
        .collect::<Vec<_>>();
    // Decommit.
    for (mut query, (mut leaf, siblings)) in queries
        .iter()
        .copied()
        .zip(proof.leaves.iter().copied().zip(proof.siblings.iter()))
    {
        for (i, ((&sibling, &alpha), layer_twiddles)) in siblings
            .iter()
            .zip(factors.iter())
            .zip(twiddles.iter().take(n_layers))
            .enumerate()
        {
            // TODO: Verify sibling decommitment.
            assert_eq!(sibling, proof.commitments[i][query ^ 1]);

            let (mut f0, mut f1) = if query & 1 == 0 {
                (leaf, sibling)
            } else {
                (sibling, leaf)
            };
            ibutterfly(
                &mut f0,
                &mut f1,
                layer_twiddles[query >> 1].inverse().into(),
            );
            leaf = f0 + alpha * f1;
            query >>= 1;
        }
        // Check against last layer
        assert_eq!(leaf, proof.last_layer[query]);
    }
}
