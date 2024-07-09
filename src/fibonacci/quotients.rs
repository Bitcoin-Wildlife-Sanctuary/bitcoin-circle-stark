use crate::constraints::{ColumnLineCoeffs, DenominatorInverseHint};
use crate::fibonacci::utils::FSOutput;
use crate::fibonacci::PerQueryQuotientHint;
use crate::fri::FieldInversionHint;
use crate::merkle_tree::MerkleTreeTwinProof;
use crate::precomputed_merkle_tree::PrecomputedMerkleTree;
use stwo_prover::core::fft::ibutterfly;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;
use stwo_prover::core::pcs::quotients::PointSample;
use stwo_prover::core::ColumnVec;

#[derive(Default, Clone, Debug)]
pub struct QuotientsOutput {
    pub fold_results: Vec<QM31>,
}

#[allow(clippy::too_many_arguments)]
pub fn compute_quotients_hints(
    precomputed_merkle_tree: &PrecomputedMerkleTree,
    fs_output: &FSOutput,
    denominator_inverses_expected: &[Vec<Vec<CM31>>],
    samples: &ColumnVec<Vec<PointSample>>,
    column_line_coeffs: &[ColumnLineCoeffs],
    merkle_proofs_traces: &[MerkleTreeTwinProof],
    merkle_proofs_compositions: &[MerkleTreeTwinProof],
    queries_parents: &[usize],
) -> (QuotientsOutput, Vec<PerQueryQuotientHint>) {
    let mut hints = vec![];
    let mut fold_results = vec![];

    for (i, queries_parent) in queries_parents.iter().enumerate() {
        let precomputed = precomputed_merkle_tree.query(queries_parent << 1);

        let denominator_inverse_hints = vec![
            DenominatorInverseHint::new(samples[0][0].point, precomputed.circle_point),
            DenominatorInverseHint::new(samples[0][1].point, precomputed.circle_point),
            DenominatorInverseHint::new(samples[0][2].point, precomputed.circle_point),
            DenominatorInverseHint::new(samples[1][0].point, precomputed.circle_point),
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

        let mut nominators = vec![];
        for column_line_coeff in column_line_coeffs.iter().take(3) {
            nominators.push(column_line_coeff.apply_twin(
                precomputed.circle_point,
                &[queried_values_left[0][0]],
                &[queried_values_right[0][0]],
            ));
        }
        nominators.push(column_line_coeffs[3].apply_twin(
            precomputed.circle_point,
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

        let eval_left = fs_output.fri_input.random_coeff.pow(6)
            * QM31::from(nominators[0].0[0] * denominator_inverses_expected[i][0][0])
            + fs_output.fri_input.random_coeff.pow(5)
                * QM31::from(nominators[1].0[0] * denominator_inverses_expected[i][1][0])
            + fs_output.fri_input.random_coeff.pow(4)
                * QM31::from(nominators[2].0[0] * denominator_inverses_expected[i][2][0])
            + (fs_output.fri_input.random_coeff.pow(3) * QM31::from(nominators[3].0[0])
                + fs_output.fri_input.random_coeff.pow(2) * QM31::from(nominators[3].0[1])
                + fs_output.fri_input.random_coeff * QM31::from(nominators[3].0[2])
                + QM31::from(nominators[3].0[3]))
                * QM31::from(denominator_inverses_expected[i][3][0]);

        let eval_right = fs_output.fri_input.random_coeff.pow(6)
            * QM31::from(nominators[0].1[0] * denominator_inverses_expected[i][0][1])
            + fs_output.fri_input.random_coeff.pow(5)
                * QM31::from(nominators[1].1[0] * denominator_inverses_expected[i][1][1])
            + fs_output.fri_input.random_coeff.pow(4)
                * QM31::from(nominators[2].1[0] * denominator_inverses_expected[i][2][1])
            + (fs_output.fri_input.random_coeff.pow(3) * QM31::from(nominators[3].1[0])
                + fs_output.fri_input.random_coeff.pow(2) * QM31::from(nominators[3].1[1])
                + fs_output.fri_input.random_coeff * QM31::from(nominators[3].1[2])
                + QM31::from(nominators[3].1[3]))
                * QM31::from(denominator_inverses_expected[i][3][1]);

        let y_inverse_hint = FieldInversionHint::from(precomputed.circle_point.y);

        let test_only_fri_answer = {
            let p = precomputed.circle_point;
            let py_inverse = p.y.inverse();

            let f_p = eval_left;
            let f_neg_p = eval_right;

            let (mut f0_px, mut f1_px) = (f_p, f_neg_p);
            ibutterfly(&mut f0_px, &mut f1_px, py_inverse);

            vec![f0_px, f1_px]
        };

        fold_results.push(
            fs_output.fri_input.circle_poly_alpha * test_only_fri_answer[1]
                + test_only_fri_answer[0],
        );

        hints.push(PerQueryQuotientHint {
            precomputed_merkle_proofs: vec![precomputed.clone()],
            denominator_inverse_hints,
            y_inverse_hint,
            test_only_fri_answer,
        });
    }

    (QuotientsOutput { fold_results }, hints)
}
