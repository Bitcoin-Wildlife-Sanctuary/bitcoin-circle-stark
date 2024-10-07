use crate::dsl::plonk::hints::fiat_shamir::FiatShamirOutput;
use crate::dsl::plonk::hints::prepare::PrepareOutput;
use crate::precomputed_merkle_tree::PrecomputedMerkleTreeProof;
use stwo_prover::core::fft::ibutterfly;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;

#[derive(Default, Clone)]
/// Hint that repeats for each query.
pub struct PerQueryQuotientHint {
    /// Precomputed tree Merkle proofs.
    pub precomputed_merkle_proofs: Vec<PrecomputedMerkleTreeProof>,
}

/// Output from the quotient step.
#[derive(Default, Clone, Debug)]
pub(crate) struct QuotientsOutput {
    /// Results to be folded.
    pub fold_results: Vec<QM31>,
}

/// Compute the quotients hints.
pub(crate) fn compute_quotients_hints(
    fs_output: &FiatShamirOutput,
    prepare_output: &PrepareOutput,
) -> (QuotientsOutput, Vec<PerQueryQuotientHint>) {
    let mut hints = vec![];
    let mut fold_results = vec![];

    for (i, queries_parent) in fs_output.queries_parents.iter().enumerate() {
        let precomputed = prepare_output
            .precomputed_merkle_tree
            .query(queries_parent << 1);

        let mut nominators = vec![
            prepare_output.column_line_coeffs[0].apply_twin(
                precomputed.circle_point,
                &[
                    fs_output.queried_values_left[i][0],
                    fs_output.queried_values_left[i][1],
                    fs_output.queried_values_left[i][2],
                    fs_output.queried_values_left[i][3],
                ],
                &[
                    fs_output.queried_values_right[i][0],
                    fs_output.queried_values_right[i][1],
                    fs_output.queried_values_right[i][2],
                    fs_output.queried_values_right[i][3],
                ],
            ),
            prepare_output.column_line_coeffs[1].apply_twin(
                precomputed.circle_point,
                &[
                    fs_output.queried_values_left[i][4],
                    fs_output.queried_values_left[i][5],
                    fs_output.queried_values_left[i][6],
                    fs_output.queried_values_left[i][7],
                    fs_output.queried_values_left[i][8],
                    fs_output.queried_values_left[i][9],
                    fs_output.queried_values_left[i][10],
                    fs_output.queried_values_left[i][11],
                ],
                &[
                    fs_output.queried_values_right[i][4],
                    fs_output.queried_values_right[i][5],
                    fs_output.queried_values_right[i][6],
                    fs_output.queried_values_right[i][7],
                    fs_output.queried_values_right[i][8],
                    fs_output.queried_values_right[i][9],
                    fs_output.queried_values_right[i][10],
                    fs_output.queried_values_right[i][11],
                ],
            ),
            prepare_output.column_line_coeffs[2].apply_twin(
                precomputed.circle_point,
                &[
                    fs_output.queried_values_left[i][8],
                    fs_output.queried_values_left[i][9],
                    fs_output.queried_values_left[i][10],
                    fs_output.queried_values_left[i][11],
                ],
                &[
                    fs_output.queried_values_right[i][8],
                    fs_output.queried_values_right[i][9],
                    fs_output.queried_values_right[i][10],
                    fs_output.queried_values_right[i][11],
                ],
            ),
            prepare_output.column_line_coeffs[3].apply_twin(
                precomputed.circle_point,
                &[
                    fs_output.queried_values_left[i][12],
                    fs_output.queried_values_left[i][13],
                    fs_output.queried_values_left[i][14],
                    fs_output.queried_values_left[i][15],
                ],
                &[
                    fs_output.queried_values_right[i][12],
                    fs_output.queried_values_right[i][13],
                    fs_output.queried_values_right[i][14],
                    fs_output.queried_values_right[i][15],
                ],
            ),
        ];

        // composition
        nominators.push(prepare_output.column_line_coeffs[4].apply_twin(
            precomputed.circle_point,
            &[
                fs_output.queried_values_left[i][16],
                fs_output.queried_values_left[i][17],
                fs_output.queried_values_left[i][18],
                fs_output.queried_values_left[i][19],
            ],
            &[
                fs_output.queried_values_right[i][16],
                fs_output.queried_values_right[i][17],
                fs_output.queried_values_right[i][18],
                fs_output.queried_values_right[i][19],
            ],
        ));

        let denominator_inverses_expected = &prepare_output.denominator_inverses_expected;

        // The computation will look as follows
        //   (alpha^20) * (alpha^3 * g_mul(X) + alpha^2 * g_a_val(X) + alpha * g_b_val(X) + g_c_val(X))
        // + (alpha^12) * (alpha^7 * g_logab1(X) + alpha^6 * g_logab2(X) + alpha^5 * g_logab3(X) + alpha^4 * g_logab4(X)
        //             + alpha^3 * g_logc1(X) + alpha^2 * g_logc2(X) + alpha^1 * g_logc3(X) + g_logc4(X))
        // + (alpha^8) * (alpha^3 * g_op(X) + alpha^2 * g_a_wire(X) + alpha * g_b_wire(X) + g_c_wire(X))
        // + (alpha^4) * (alpha^3 * g_compose1(X) + alpha^2 * g_compose2(X) + alpha * g_compose3(X) + g_compose4(X))
        //
        // divided by v_0(X)
        //
        // plus
        //
        // (alpha^3 * g_logc_shifted_1(X) + alpha^2 * g_logc_shifted_2(X) + alpha^2 * g_logc_shifted_3(X) + g_logc_shifted_4(X))
        //
        // divided by v_1(X)

        let alpha = fs_output.line_batch_random_coeff;

        let mut eval_left = alpha.pow(20)
            * (alpha.pow(3) * QM31::from(nominators[0].0[0])
                + alpha.pow(2) * QM31::from(nominators[0].0[1])
                + alpha * QM31::from(nominators[0].0[2])
                + QM31::from(nominators[0].0[3]));

        eval_left += alpha.pow(12)
            * (alpha.pow(7) * QM31::from(nominators[1].0[0])
                + alpha.pow(6) * QM31::from(nominators[1].0[1])
                + alpha.pow(5) * QM31::from(nominators[1].0[2])
                + alpha.pow(4) * QM31::from(nominators[1].0[3]));

        eval_left += alpha.pow(12)
            * (alpha.pow(3) * QM31::from(nominators[1].0[4])
                + alpha.pow(2) * QM31::from(nominators[1].0[5])
                + alpha * QM31::from(nominators[1].0[6])
                + QM31::from(nominators[1].0[7]));

        eval_left += alpha.pow(8)
            * (alpha.pow(3) * QM31::from(nominators[3].0[0])
                + alpha.pow(2) * QM31::from(nominators[3].0[1])
                + alpha * QM31::from(nominators[3].0[2])
                + QM31::from(nominators[3].0[3]));

        eval_left += alpha.pow(4)
            * (alpha.pow(3) * QM31::from(nominators[4].0[0])
                + alpha.pow(2) * QM31::from(nominators[4].0[1])
                + alpha * QM31::from(nominators[4].0[2])
                + QM31::from(nominators[4].0[3]));

        eval_left *= QM31::from(denominator_inverses_expected[i][0][0]);

        eval_left += (alpha.pow(3) * QM31::from(nominators[2].0[0])
            + alpha.pow(2) * QM31::from(nominators[2].0[1])
            + alpha * QM31::from(nominators[2].0[2])
            + QM31::from(nominators[2].0[3]))
            * QM31::from(denominator_inverses_expected[i][1][0]);

        let mut eval_right = alpha.pow(20)
            * (alpha.pow(3) * QM31::from(nominators[0].1[0])
                + alpha.pow(2) * QM31::from(nominators[0].1[1])
                + alpha * QM31::from(nominators[0].1[2])
                + QM31::from(nominators[0].1[3]));

        eval_right += alpha.pow(12)
            * (alpha.pow(7) * QM31::from(nominators[1].1[0])
                + alpha.pow(6) * QM31::from(nominators[1].1[1])
                + alpha.pow(5) * QM31::from(nominators[1].1[2])
                + alpha.pow(4) * QM31::from(nominators[1].1[3]));

        eval_right += alpha.pow(12)
            * (alpha.pow(3) * QM31::from(nominators[1].1[4])
                + alpha.pow(2) * QM31::from(nominators[1].1[5])
                + alpha * QM31::from(nominators[1].1[6])
                + QM31::from(nominators[1].1[7]));

        eval_right += alpha.pow(8)
            * (alpha.pow(3) * QM31::from(nominators[3].1[0])
                + alpha.pow(2) * QM31::from(nominators[3].1[1])
                + alpha * QM31::from(nominators[3].1[2])
                + QM31::from(nominators[3].1[3]));

        eval_right += alpha.pow(4)
            * (alpha.pow(3) * QM31::from(nominators[4].1[0])
                + alpha.pow(2) * QM31::from(nominators[4].1[1])
                + alpha * QM31::from(nominators[4].1[2])
                + QM31::from(nominators[4].1[3]));

        eval_right *= QM31::from(denominator_inverses_expected[i][0][1]);

        eval_right += (alpha.pow(3) * QM31::from(nominators[2].1[0])
            + alpha.pow(2) * QM31::from(nominators[2].1[1])
            + alpha * QM31::from(nominators[2].1[2])
            + QM31::from(nominators[2].1[3]))
            * QM31::from(denominator_inverses_expected[i][1][1]);

        let fri_answer = {
            let p = precomputed.circle_point;
            let py_inverse = p.y.inverse();

            let f_p = eval_left;
            let f_neg_p = eval_right;

            let (mut f0_px, mut f1_px) = (f_p, f_neg_p);
            ibutterfly(&mut f0_px, &mut f1_px, py_inverse);

            vec![f0_px, f1_px]
        };

        fold_results.push(fs_output.circle_poly_alpha * fri_answer[1] + fri_answer[0]);

        hints.push(PerQueryQuotientHint {
            precomputed_merkle_proofs: vec![precomputed.clone()],
        });
    }

    (QuotientsOutput { fold_results }, hints)
}
