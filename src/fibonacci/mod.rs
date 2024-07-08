mod bitcoin_script;

mod fiat_shamir;
mod utils;

pub use bitcoin_script::*;
use itertools::Itertools;
use std::iter::zip;

use crate::constraints::{
    ColumnLineCoeffs, ColumnLineCoeffsHint, DenominatorInverseHint, PreparedPairVanishingHint,
};
use crate::fibonacci::fiat_shamir::FiatShamirHints;
use crate::fri::FieldInversionHint;
use crate::merkle_tree::{MerkleTree, MerkleTreeTwinProof};
use crate::precomputed_merkle_tree::{PrecomputedMerkleTree, PrecomputedMerkleTreeProof};
use crate::treepp::pushable::{Builder, Pushable};
use stwo_prover::core::air::Air;
use stwo_prover::core::backend::cpu::quotients::{batch_random_coeffs, denominator_inverses};
use stwo_prover::core::backend::CpuBackend;
use stwo_prover::core::channel::BWSSha256Channel;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::constraints::complex_conjugate_line_coeffs_normalized;
use stwo_prover::core::fft::ibutterfly;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fields::FieldExpOps;
use stwo_prover::core::fri::get_opening_positions;
use stwo_prover::core::pcs::quotients::{fri_answers, ColumnSampleBatch, PointSample};
use stwo_prover::core::pcs::TreeVec;
use stwo_prover::core::poly::circle::{CanonicCoset, SecureCirclePoly};
use stwo_prover::core::prover::{
    InvalidOodsSampleStructure, StarkProof, VerificationError, N_QUERIES,
};
use stwo_prover::core::{ColumnVec, ComponentVec};
use stwo_prover::examples::fibonacci::air::FibonacciAir;

/// All the hints for the verifier (note: proof is also provided as a hint).
pub struct VerifierHints {
    /// Fiat-Shamir hints.
    pub fiat_shamir_hints: FiatShamirHints,

    /// Merkle proofs for the trace Merkle tree.
    pub merkle_proofs_traces: Vec<MerkleTreeTwinProof>,

    /// Merkle proofs for the composition Merkle tree.
    pub merkle_proofs_compositions: Vec<MerkleTreeTwinProof>,

    /// Column line coeff hints.
    pub column_line_coeffs_hints: Vec<ColumnLineCoeffsHint>,

    /// Per query hints.
    pub per_query_hints: Vec<PerQueryHint>,
}

/// Hint that repeats for each query.
pub struct PerQueryHint {
    /// Prepared pair vanishing hints.
    pub prepared_pair_vanishing_hints: Vec<PreparedPairVanishingHint>,

    /// Precomputed tree Merkle proofs.
    pub precomputed_merkle_proofs: Vec<PrecomputedMerkleTreeProof>,

    /// Denominator inverse hints.
    pub denominator_inverse_hints: Vec<DenominatorInverseHint>,

    /// Y inverse hint.
    pub y_inverse_hint: FieldInversionHint,

    /// Test-only: the FRI answer.
    pub test_only_fri_answer: Vec<QM31>,
}

impl Pushable for &VerifierHints {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        builder = (&self.fiat_shamir_hints).bitcoin_script_push(builder);
        for proof in self.merkle_proofs_traces.iter() {
            builder = proof.bitcoin_script_push(builder);
        }
        for proof in self.merkle_proofs_compositions.iter() {
            builder = proof.bitcoin_script_push(builder);
        }
        for hint in self.column_line_coeffs_hints.iter() {
            builder = hint.bitcoin_script_push(builder);
        }
        for hint in self.per_query_hints.iter() {
            builder = hint.bitcoin_script_push(builder);
        }
        builder
    }
}

impl Pushable for VerifierHints {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        (&self).bitcoin_script_push(builder)
    }
}

impl Pushable for &PerQueryHint {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        for hint in self.prepared_pair_vanishing_hints.iter() {
            builder = hint.bitcoin_script_push(builder);
        }
        for proof in self.precomputed_merkle_proofs.iter() {
            builder = proof.bitcoin_script_push(builder);
        }
        for hint in self.denominator_inverse_hints.iter() {
            builder = hint.bitcoin_script_push(builder);
        }
        builder = (&self.y_inverse_hint).bitcoin_script_push(builder);
        for elem in self.test_only_fri_answer.iter().rev() {
            builder = elem.bitcoin_script_push(builder);
        }
        builder
    }
}

impl Pushable for PerQueryHint {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        (&self).bitcoin_script_push(builder)
    }
}

/// A verifier program that generates hints.
pub fn verify_with_hints(
    proof: StarkProof,
    air: &FibonacciAir,
    channel: &mut BWSSha256Channel,
) -> Result<VerifierHints, VerificationError> {
    let fs_output = utils::generate_fs_hints(proof.clone(), channel, air).unwrap();

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
        assert!(MerkleTree::verify_twin(
            &proof.commitments[0],
            (fs_output.fri_input.max_column_log_degree_bound
                + fs_output.fri_input.fri_log_blowup_factor) as usize,
            twin_proof,
            query << 1
        ));
    }

    for (&query, twin_proof) in queries_parents
        .iter()
        .zip(merkle_proofs_compositions.iter())
    {
        assert!(MerkleTree::verify_twin(
            &proof.commitments[1],
            (fs_output.fri_input.max_column_log_degree_bound
                + fs_output.fri_input.fri_log_blowup_factor) as usize,
            twin_proof,
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
        .zip_cols(&proof.commitment_scheme_proof.sampled_values)
        .map_cols(|(sampled_points, sampled_values)| {
            zip(sampled_points, sampled_values)
                .map(|(point, &value)| PointSample { point, value })
                .collect_vec()
        })
        .flatten();

    let colume_sample_batches =
        ColumnSampleBatch::new_vec(&samples.iter().collect::<Vec<&Vec<PointSample>>>());

    let expected_line_coeffs: Vec<Vec<(CM31, CM31)>> = {
        colume_sample_batches
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
        { batch_random_coeffs(&colume_sample_batches, fs_output.fri_input.random_coeff) };
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
    let first_proof = precomputed_merkle_tree.query(queries_parents[0] << 1);

    let commitment_domain = CanonicCoset::new(
        fs_output.fri_input.max_column_log_degree_bound + fs_output.fri_input.fri_log_blowup_factor,
    )
    .circle_domain();

    let denominator_inverses_expected = query_domain
        .1
        .iter()
        .map(|subdomain| {
            let domain = subdomain.to_circle_domain(&commitment_domain);
            denominator_inverses(&colume_sample_batches, domain)
        })
        .collect::<Vec<_>>();
    assert_eq!(denominator_inverses_expected.len(), N_QUERIES);

    let denominator_inverse_hints = vec![
        DenominatorInverseHint::new(samples[0][0].point, first_proof.circle_point),
        DenominatorInverseHint::new(samples[0][1].point, first_proof.circle_point),
        DenominatorInverseHint::new(samples[0][2].point, first_proof.circle_point),
        DenominatorInverseHint::new(samples[1][0].point, first_proof.circle_point),
    ];

    let mut queried_values_left = vec![];
    let mut queried_values_right = vec![];
    for (trace, composition) in merkle_proofs_traces
        .iter()
        .zip(merkle_proofs_compositions.iter())
    {
        let mut left_vec = vec![];
        let mut right_vec = vec![];
        for (&left, &right) in trace
            .left
            .iter()
            .zip(trace.right.iter())
            .chain(composition.left.iter().zip(composition.right.iter()))
        {
            left_vec.push(left);
            right_vec.push(right);
        }
        queried_values_left.push(left_vec);
        queried_values_right.push(right_vec);
    }

    let mut flatten_values = vec![vec![]; 5];
    for (l, r) in queried_values_left.iter().zip(queried_values_right.iter()) {
        for ((flatten, &ll), &rr) in flatten_values.iter_mut().zip_eq(l.iter()).zip_eq(r.iter()) {
            flatten.push(ll);
            flatten.push(rr);
        }
    }

    let fri_answers = fri_answers(
        fs_output
            .fri_input
            .commitment_scheme_column_log_sizes
            .flatten()
            .into_iter()
            .collect(),
        &samples,
        fs_output.fri_input.random_coeff,
        fri_query_domains,
        &flatten_values,
    )?;

    let mut nominators = vec![];
    for column_line_coeff in column_line_coeffs.iter().take(3) {
        nominators.push(column_line_coeff.apply_twin(
            first_proof.circle_point,
            &[queried_values_left[0][0]],
            &[queried_values_right[0][0]],
        ));
    }
    nominators.push(column_line_coeffs[3].apply_twin(
        first_proof.circle_point,
        &[
            queried_values_left[0][1],
            queried_values_left[0][2],
            queried_values_left[0][3],
            queried_values_left[0][4],
        ],
        &[
            queried_values_right[0][1],
            queried_values_right[0][2],
            queried_values_right[0][3],
            queried_values_right[0][4],
        ],
    ));

    let expected_eval_left = fs_output.fri_input.random_coeff.pow(6)
        * QM31::from(nominators[0].0[0] * denominator_inverses_expected[0][0][0])
        + fs_output.fri_input.random_coeff.pow(5)
            * QM31::from(nominators[1].0[0] * denominator_inverses_expected[0][1][0])
        + fs_output.fri_input.random_coeff.pow(4)
            * QM31::from(nominators[2].0[0] * denominator_inverses_expected[0][2][0])
        + (fs_output.fri_input.random_coeff.pow(3) * QM31::from(nominators[3].0[0])
            + fs_output.fri_input.random_coeff.pow(2) * QM31::from(nominators[3].0[1])
            + fs_output.fri_input.random_coeff * QM31::from(nominators[3].0[2])
            + QM31::from(nominators[3].0[3]))
            * QM31::from(denominator_inverses_expected[0][3][0]);

    assert_eq!(
        expected_eval_left,
        fri_answers[0].subcircle_evals[0].values[0]
    );

    let expected_eval_right = fs_output.fri_input.random_coeff.pow(6)
        * QM31::from(nominators[0].1[0] * denominator_inverses_expected[0][0][1])
        + fs_output.fri_input.random_coeff.pow(5)
            * QM31::from(nominators[1].1[0] * denominator_inverses_expected[0][1][1])
        + fs_output.fri_input.random_coeff.pow(4)
            * QM31::from(nominators[2].1[0] * denominator_inverses_expected[0][2][1])
        + (fs_output.fri_input.random_coeff.pow(3) * QM31::from(nominators[3].1[0])
            + fs_output.fri_input.random_coeff.pow(2) * QM31::from(nominators[3].1[1])
            + fs_output.fri_input.random_coeff * QM31::from(nominators[3].1[2])
            + QM31::from(nominators[3].1[3]))
            * QM31::from(denominator_inverses_expected[0][3][1]);

    assert_eq!(
        expected_eval_right,
        fri_answers[0].subcircle_evals[0].values[1]
    );

    let y_inverse_hint = FieldInversionHint::from(first_proof.circle_point.y);

    let test_only_fri_answer = {
        let p = first_proof.circle_point;
        let py_inverse = p.y.inverse();

        let f_p = expected_eval_left;
        let f_neg_p = expected_eval_right;

        let (mut f0_px, mut f1_px) = (f_p, f_neg_p);
        ibutterfly(&mut f0_px, &mut f1_px, py_inverse);

        vec![f0_px, f1_px]
    };

    let first_fold =
        fs_output.fri_input.circle_poly_alpha * test_only_fri_answer[1] + test_only_fri_answer[0];

    let _ = first_fold;
    let _ = expected_line_coeffs;
    let _ = fs_output.fri_input.last_layer_domain;
    let _ = fs_output.fri_input.circle_poly_alpha;
    let _ = fs_output.fri_input.random_coeff;

    let first_query_hint = PerQueryHint {
        prepared_pair_vanishing_hints,
        precomputed_merkle_proofs: vec![first_proof.clone()],
        denominator_inverse_hints,
        y_inverse_hint,
        test_only_fri_answer,
    };

    Ok(VerifierHints {
        fiat_shamir_hints: fs_output.fiat_shamir_hints,
        merkle_proofs_traces,
        merkle_proofs_compositions,
        column_line_coeffs_hints,
        per_query_hints: vec![first_query_hint],
    })
}

fn sampled_values_to_mask(
    air: &impl Air,
    mut sampled_values: TreeVec<ColumnVec<Vec<SecureField>>>,
) -> Result<(ComponentVec<Vec<SecureField>>, SecureField), InvalidOodsSampleStructure> {
    let composition_partial_sampled_values =
        sampled_values.pop().ok_or(InvalidOodsSampleStructure)?;
    let composition_oods_value = SecureCirclePoly::<CpuBackend>::eval_from_partial_evals(
        composition_partial_sampled_values
            .iter()
            .flatten()
            .cloned()
            .collect_vec()
            .try_into()
            .map_err(|_| InvalidOodsSampleStructure)?,
    );

    // Retrieve sampled mask values for each component.
    let flat_trace_values = &mut sampled_values
        .pop()
        .ok_or(InvalidOodsSampleStructure)?
        .into_iter();
    let trace_oods_values = ComponentVec(
        air.components()
            .iter()
            .map(|c| {
                flat_trace_values
                    .take(c.mask_points(CirclePoint::zero()).len())
                    .collect_vec()
            })
            .collect(),
    );

    Ok((trace_oods_values, composition_oods_value))
}

#[cfg(test)]
mod test {
    use stwo_prover::core::channel::{BWSSha256Channel, Channel};
    use stwo_prover::core::fields::m31::{BaseField, M31};
    use stwo_prover::core::fields::IntoSlice;
    use stwo_prover::core::prover::{prove, verify};
    use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hasher;
    use stwo_prover::core::vcs::hasher::Hasher;
    use stwo_prover::examples::fibonacci::Fibonacci;

    #[test]
    fn test_fib_prove() {
        const FIB_LOG_SIZE: u32 = 5;
        let fib = Fibonacci::new(FIB_LOG_SIZE, M31::reduce(443693538));

        let trace = fib.get_trace();
        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        let proof = prove(&fib.air, channel, vec![trace]).unwrap();

        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        verify(proof, &fib.air, channel).unwrap()
    }
}
