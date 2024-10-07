use crate::constraints::ColumnLineCoeffs;
use crate::dsl::plonk::hints::fiat_shamir::FiatShamirOutput;
use crate::precomputed_merkle_tree::PrecomputedMerkleTree;
use itertools::Itertools;
use std::iter::zip;
use stwo_prover::core::backend::cpu::quotients::denominator_inverses;
use stwo_prover::core::constraints::complex_conjugate_line_coeffs_normalized;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::pcs::quotients::{ColumnSampleBatch, PointSample};
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::prover::{StarkProof, VerificationError, N_QUERIES};
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;

/// Prepare Output
pub struct PrepareOutput {
    /// Precomputed Merkle tree for point and twiddles.
    pub precomputed_merkle_tree: PrecomputedMerkleTree,

    /// Expected denominator inverses.
    pub denominator_inverses_expected: Vec<Vec<Vec<CM31>>>,

    /// Column line coefficients.
    pub column_line_coeffs: Vec<ColumnLineCoeffs>,
}

/// prepare output for quotients and verifier hints
pub fn compute_prepare_hints(
    fs_output: &FiatShamirOutput,
    proof: &StarkProof<Sha256MerkleHasher>,
) -> Result<PrepareOutput, VerificationError> {
    let column_size: Vec<u32> = fs_output
        .commitment_scheme_column_log_sizes
        .clone()
        .flatten()
        .into_iter()
        .dedup()
        .collect();
    assert_eq!(column_size.len(), 1);
    assert_eq!(
        column_size[0],
        fs_output.max_column_log_degree_bound + fs_output.fri_log_blowup_factor
    );

    assert_eq!(proof.commitment_scheme_proof.sampled_values.0.len(), 4);

    // trace polynomials, four polynomials
    assert_eq!(proof.commitment_scheme_proof.sampled_values.0[0].len(), 4);
    for i in 0..4 {
        assert_eq!(
            proof.commitment_scheme_proof.sampled_values.0[0][i].len(),
            1
        );
    }

    // interaction polynomials, eight polynomials
    assert_eq!(proof.commitment_scheme_proof.sampled_values.0[1].len(), 8);
    for i in 0..4 {
        assert_eq!(
            proof.commitment_scheme_proof.sampled_values.0[1][i].len(),
            1
        );
    }
    for i in 4..8 {
        assert_eq!(
            proof.commitment_scheme_proof.sampled_values.0[1][i].len(),
            2
        );
    }

    // constant polynomials, four polynomials
    assert_eq!(proof.commitment_scheme_proof.sampled_values.0[2].len(), 4);
    for i in 0..4 {
        assert_eq!(
            proof.commitment_scheme_proof.sampled_values.0[2][i].len(),
            1
        );
    }

    // composition polynomials, four polynomials
    assert_eq!(proof.commitment_scheme_proof.sampled_values.0[3].len(), 4);
    for i in 0..4 {
        assert_eq!(
            proof.commitment_scheme_proof.sampled_values.0[3][i].len(),
            1
        );
    }

    let precomputed_merkle_tree = PrecomputedMerkleTree::new(
        (fs_output.max_column_log_degree_bound + fs_output.fri_log_blowup_factor - 1) as usize,
    );

    // construct the list of samples
    // Answer FRI queries.
    let samples = fs_output
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

    let column_line_coeffs_trace = ColumnLineCoeffs::from_values_and_point(
        &[
            samples[0][0].value,
            samples[1][0].value,
            samples[2][0].value,
            samples[3][0].value,
        ],
        samples[0][0].point,
    );

    for i in 0..4 {
        assert_eq!(
            expected_line_coeffs[0][i].0,
            column_line_coeffs_trace.fp_imag_div_y_imag[i],
        );
        assert_eq!(
            expected_line_coeffs[0][i].1,
            column_line_coeffs_trace.cross_term[i],
        );
    }

    let column_line_coeffs_interaction = ColumnLineCoeffs::from_values_and_point(
        &[
            samples[4][0].value,
            samples[5][0].value,
            samples[6][0].value,
            samples[7][0].value,
            samples[8][0].value,
            samples[9][0].value,
            samples[10][0].value,
            samples[11][0].value,
        ],
        samples[4][0].point,
    );

    for i in 0..8 {
        assert_eq!(
            expected_line_coeffs[0][4 + i].0,
            column_line_coeffs_interaction.fp_imag_div_y_imag[i],
        );
        assert_eq!(
            expected_line_coeffs[0][4 + i].1,
            column_line_coeffs_interaction.cross_term[i],
        );
    }

    let column_line_coeffs_interaction_shifted = ColumnLineCoeffs::from_values_and_point(
        &[
            samples[8][1].value,
            samples[9][1].value,
            samples[10][1].value,
            samples[11][1].value,
        ],
        samples[8][1].point,
    );

    for i in 0..4 {
        assert_eq!(
            expected_line_coeffs[1][i].0,
            column_line_coeffs_interaction_shifted.fp_imag_div_y_imag[i],
        );
        assert_eq!(
            expected_line_coeffs[1][i].1,
            column_line_coeffs_interaction_shifted.cross_term[i],
        );
    }

    let column_line_coeffs_constant = ColumnLineCoeffs::from_values_and_point(
        &[
            samples[12][0].value,
            samples[13][0].value,
            samples[14][0].value,
            samples[15][0].value,
        ],
        samples[12][0].point,
    );

    for i in 0..4 {
        assert_eq!(
            expected_line_coeffs[0][12 + i].0,
            column_line_coeffs_constant.fp_imag_div_y_imag[i],
        );
        assert_eq!(
            expected_line_coeffs[0][12 + i].1,
            column_line_coeffs_constant.cross_term[i],
        );
    }

    let column_line_coeffs_composition = ColumnLineCoeffs::from_values_and_point(
        &[
            samples[16][0].value,
            samples[17][0].value,
            samples[18][0].value,
            samples[19][0].value,
        ],
        samples[16][0].point,
    );

    for i in 0..4 {
        assert_eq!(
            expected_line_coeffs[0][16 + i].0,
            column_line_coeffs_composition.fp_imag_div_y_imag[i],
        );
        assert_eq!(
            expected_line_coeffs[0][16 + i].1,
            column_line_coeffs_composition.cross_term[i],
        );
    }

    let commitment_domain =
        CanonicCoset::new(fs_output.max_column_log_degree_bound + fs_output.fri_log_blowup_factor)
            .circle_domain();

    let denominator_inverses_expected = fs_output
        .query_subcircle_domain
        .iter()
        .map(|subdomain| {
            let domain = subdomain.to_circle_domain(&commitment_domain);
            denominator_inverses(&column_sample_batches, domain)
        })
        .collect::<Vec<_>>();
    assert_eq!(denominator_inverses_expected.len(), N_QUERIES);

    Ok(PrepareOutput {
        precomputed_merkle_tree,
        denominator_inverses_expected,
        column_line_coeffs: vec![
            column_line_coeffs_trace,
            column_line_coeffs_interaction,
            column_line_coeffs_interaction_shifted,
            column_line_coeffs_constant,
            column_line_coeffs_composition,
        ],
    })
}
