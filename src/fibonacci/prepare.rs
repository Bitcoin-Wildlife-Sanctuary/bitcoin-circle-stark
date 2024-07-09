use itertools::Itertools;
use std::iter::zip;
use stwo_prover::core::{
    backend::cpu::quotients::{batch_random_coeffs, denominator_inverses},
    constraints::complex_conjugate_line_coeffs_normalized,
    fields::{cm31::CM31, FieldExpOps},
    fri::get_opening_positions,
    pcs::quotients::{ColumnSampleBatch, PointSample},
    poly::circle::CanonicCoset,
    prover::{StarkProof, VerificationError, N_QUERIES},
};

use crate::{
    constraints::{ColumnLineCoeffs, ColumnLineCoeffsHint, PreparedPairVanishingHint},
    fibonacci::fiat_shamir::FSOutput,
    merkle_tree::MerkleTreeTwinProof,
    precomputed_merkle_tree::PrecomputedMerkleTree,
    treepp::pushable::{Builder, Pushable},
};

/// Column Line Coefficients and Pair Vanishing Hints
pub struct ColumnLineCoeffPairVanishingHints {
    /// Column line coeff hints.
    pub column_line_coeffs_hints: Vec<ColumnLineCoeffsHint>,

    /// Prepared pair vanishing hints.
    pub prepared_pair_vanishing_hints: Vec<PreparedPairVanishingHint>,
}

impl Pushable for &ColumnLineCoeffPairVanishingHints {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        for hint in self.column_line_coeffs_hints.iter() {
            builder = hint.bitcoin_script_push(builder);
        }
        for hint in self.prepared_pair_vanishing_hints.iter() {
            builder = hint.bitcoin_script_push(builder);
        }
        builder
    }
}

impl Pushable for ColumnLineCoeffPairVanishingHints {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        (&self).bitcoin_script_push(builder)
    }
}

/// Prepare Output
pub struct PrepareOutput {
    pub precomputed_merkle_tree: PrecomputedMerkleTree,
    pub denominator_inverses_expected: Vec<Vec<Vec<CM31>>>,
    pub samples: Vec<Vec<PointSample>>,
    pub column_line_coeffs: Vec<ColumnLineCoeffs>,
    pub merkle_proofs_traces: Vec<MerkleTreeTwinProof>,
    pub merkle_proofs_compositions: Vec<MerkleTreeTwinProof>,
    pub queries_parents: Vec<usize>,
    pub column_line_coeff_pair_vanishing_hints: ColumnLineCoeffPairVanishingHints,
}

/// prepare output for quotients and verifier hints
pub fn prepare(
    fs_output: &FSOutput,
    proof: &StarkProof,
) -> Result<PrepareOutput, VerificationError> {
    let fri_query_domains = get_opening_positions(
        &fs_output.fri_input.queries,
        &fs_output.fri_input.column_log_sizes,
    );

    assert_eq!(fri_query_domains.len(), 1);
    let query_domain = fri_query_domains.first_key_value().unwrap();
    assert_eq!(
        *query_domain.0,
        fs_output.fri_input.max_column_log_degree_bound + fs_output.fri_input.fri_log_blowup_factor
    );

    let queries_parents: Vec<usize> = query_domain
        .1
        .iter()
        .map(|subdomain| {
            assert_eq!(subdomain.log_size, 1);
            subdomain.coset_index
        })
        .collect();

    let merkle_proofs_traces = MerkleTreeTwinProof::from_stwo_proof(
        (fs_output.fri_input.max_column_log_degree_bound
            + fs_output.fri_input.fri_log_blowup_factor) as usize,
        &queries_parents,
        &proof.commitment_scheme_proof.queried_values[0],
        &proof.commitment_scheme_proof.decommitments[0],
    );
    let merkle_proofs_compositions = MerkleTreeTwinProof::from_stwo_proof(
        (fs_output.fri_input.max_column_log_degree_bound
            + fs_output.fri_input.fri_log_blowup_factor) as usize,
        &queries_parents,
        &proof.commitment_scheme_proof.queried_values[1],
        &proof.commitment_scheme_proof.decommitments[1],
    );

    for (&query, twin_proof) in queries_parents.iter().zip(merkle_proofs_traces.iter()) {
        assert!(twin_proof.verify(
            &proof.commitments[0],
            (fs_output.fri_input.max_column_log_degree_bound
                + fs_output.fri_input.fri_log_blowup_factor) as usize,
            query << 1
        ));
    }

    for (&query, twin_proof) in queries_parents
        .iter()
        .zip(merkle_proofs_compositions.iter())
    {
        assert!(twin_proof.verify(
            &proof.commitments[1],
            (fs_output.fri_input.max_column_log_degree_bound
                + fs_output.fri_input.fri_log_blowup_factor) as usize,
            query << 1
        ));
    }

    let column_size: Vec<u32> = fs_output
        .fri_input
        .commitment_scheme_column_log_sizes
        .clone()
        .flatten()
        .into_iter()
        .dedup()
        .collect();
    assert_eq!(column_size.len(), 1);
    assert_eq!(
        column_size[0],
        fs_output.fri_input.max_column_log_degree_bound + fs_output.fri_input.fri_log_blowup_factor
    );

    // trace polynomials are evaluated on oods, oods+1, oods+2
    assert_eq!(proof.commitment_scheme_proof.sampled_values.0[0].len(), 1);
    assert_eq!(
        proof.commitment_scheme_proof.sampled_values.0[0][0].len(),
        3
    );

    // composition polynomials are evaluated on oods 4 times
    assert_eq!(proof.commitment_scheme_proof.sampled_values.0[1].len(), 4);
    assert_eq!(
        proof.commitment_scheme_proof.sampled_values.0[1][0].len(),
        1
    );

    // construct the list of samples
    // Answer FRI queries.
    let samples = fs_output
        .fri_input
        .sampled_points
        .clone()
        .zip_cols(&proof.commitment_scheme_proof.sampled_values)
        .map_cols(|(sampled_points, sampled_values)| {
            zip(sampled_points, sampled_values)
                .map(|(point, &value)| PointSample { point, value })
                .collect_vec()
        })
        .flatten();

    let column_sample_batches =
        ColumnSampleBatch::new_vec(&samples.iter().collect::<Vec<&Vec<PointSample>>>());

    let expected_line_coeffs: Vec<Vec<(CM31, CM31)>> = {
        column_sample_batches
            .iter()
            .map(|sample_batch| {
                sample_batch
                    .columns_and_values
                    .iter()
                    .map(|(_, sampled_value)| {
                        let sample = PointSample {
                            point: sample_batch.point,
                            value: *sampled_value,
                        };
                        // defer the applying of alpha for the composition to a later step
                        complex_conjugate_line_coeffs_normalized(&sample)
                    })
                    .collect()
            })
            .collect()
    };

    let column_line_coeffs = vec![
        ColumnLineCoeffs::from_values_and_point(&[samples[0][0].value], samples[0][0].point),
        ColumnLineCoeffs::from_values_and_point(&[samples[0][1].value], samples[0][1].point),
        ColumnLineCoeffs::from_values_and_point(&[samples[0][2].value], samples[0][2].point),
        ColumnLineCoeffs::from_values_and_point(
            &[
                fs_output.fri_input.sample_values[1][0][0],
                fs_output.fri_input.sample_values[1][1][0],
                fs_output.fri_input.sample_values[1][2][0],
                fs_output.fri_input.sample_values[1][3][0],
            ],
            samples[1][0].point,
        ),
    ];

    for i in 0..3 {
        assert_eq!(
            expected_line_coeffs[i][0].0,
            column_line_coeffs[i].fp_imag_div_y_imag[0]
        );
        assert_eq!(
            expected_line_coeffs[i][0].1,
            column_line_coeffs[i].cross_term[0]
        );
    }
    for j in 0..4 {
        assert_eq!(
            expected_line_coeffs[3][j].0,
            column_line_coeffs[3].fp_imag_div_y_imag[j]
        );
        assert_eq!(
            expected_line_coeffs[3][j].1,
            column_line_coeffs[3].cross_term[j]
        );
    }

    let column_line_coeffs_hints = vec![
        ColumnLineCoeffsHint::from(samples[0][0].point),
        ColumnLineCoeffsHint::from(samples[0][1].point),
        ColumnLineCoeffsHint::from(samples[0][2].point),
        ColumnLineCoeffsHint::from(samples[1][0].point),
    ];

    let prepared_pair_vanishing_hints = vec![
        PreparedPairVanishingHint::from(samples[0][0].point),
        PreparedPairVanishingHint::from(samples[0][1].point),
        PreparedPairVanishingHint::from(samples[0][2].point),
        PreparedPairVanishingHint::from(samples[1][0].point),
    ];

    let expected_batch_random_coeffs =
        { batch_random_coeffs(&column_sample_batches, fs_output.fri_input.random_coeff) };
    assert_eq!(
        expected_batch_random_coeffs[0],
        fs_output.fri_input.random_coeff
    );
    assert_eq!(
        expected_batch_random_coeffs[1],
        fs_output.fri_input.random_coeff
    );
    assert_eq!(
        expected_batch_random_coeffs[2],
        fs_output.fri_input.random_coeff
    );
    assert_eq!(
        expected_batch_random_coeffs[3],
        fs_output.fri_input.random_coeff.square().square()
    );

    let precomputed_merkle_tree = PrecomputedMerkleTree::new(
        (fs_output.fri_input.max_column_log_degree_bound
            + fs_output.fri_input.fri_log_blowup_factor
            - 1) as usize,
    );

    let commitment_domain = CanonicCoset::new(
        fs_output.fri_input.max_column_log_degree_bound + fs_output.fri_input.fri_log_blowup_factor,
    )
    .circle_domain();

    let denominator_inverses_expected = query_domain
        .1
        .iter()
        .map(|subdomain| {
            let domain = subdomain.to_circle_domain(&commitment_domain);
            denominator_inverses(&column_sample_batches, domain)
        })
        .collect::<Vec<_>>();
    assert_eq!(denominator_inverses_expected.len(), N_QUERIES);

    let column_line_coeff_pair_vanishing_hints = ColumnLineCoeffPairVanishingHints {
        column_line_coeffs_hints,
        prepared_pair_vanishing_hints,
    };

    Ok(PrepareOutput {
        precomputed_merkle_tree,
        denominator_inverses_expected,
        samples,
        column_line_coeffs,
        merkle_proofs_traces,
        merkle_proofs_compositions,
        queries_parents,
        column_line_coeff_pair_vanishing_hints,
    })
}
