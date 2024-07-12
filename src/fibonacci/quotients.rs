use crate::constraints::DenominatorInverseHint;
use crate::fibonacci::fiat_shamir::FiatShamirOutput;
use crate::fibonacci::prepare::PrepareOutput;
use crate::precomputed_merkle_tree::PrecomputedMerkleTreeProof;
use crate::treepp::pushable::{Builder, Pushable};
use stwo_prover::core::fft::ibutterfly;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;

#[derive(Default, Clone, Debug)]
pub struct QuotientsOutput {
    pub fold_results: Vec<QM31>,
}

#[allow(clippy::too_many_arguments)]
pub fn compute_quotients_hints(
    fs_output: &FiatShamirOutput,
    prepare_output: &PrepareOutput,
) -> (QuotientsOutput, Vec<PerQueryQuotientHint>) {
    let mut hints = vec![];
    let mut fold_results = vec![];

    for (i, queries_parent) in fs_output.queries_parents.iter().enumerate() {
        let precomputed = prepare_output
            .precomputed_merkle_tree
            .query(queries_parent << 1);

        let denominator_inverse_hints = vec![
            DenominatorInverseHint::new(
                prepare_output.samples[0][0].point,
                precomputed.circle_point,
            ),
            DenominatorInverseHint::new(
                prepare_output.samples[0][1].point,
                precomputed.circle_point,
            ),
            DenominatorInverseHint::new(
                prepare_output.samples[0][2].point,
                precomputed.circle_point,
            ),
            DenominatorInverseHint::new(
                prepare_output.samples[1][0].point,
                precomputed.circle_point,
            ),
        ];

        let mut nominators = vec![];
        for column_line_coeff in prepare_output.column_line_coeffs.iter().take(3) {
            nominators.push(column_line_coeff.apply_twin(
                precomputed.circle_point,
                &[fs_output.queried_values_left[i][0]],
                &[fs_output.queried_values_right[i][0]],
            ));
        }
        nominators.push(prepare_output.column_line_coeffs[3].apply_twin(
            precomputed.circle_point,
            &[
                fs_output.queried_values_left[i][1],
                fs_output.queried_values_left[i][2],
                fs_output.queried_values_left[i][3],
                fs_output.queried_values_left[i][4],
            ],
            &[
                fs_output.queried_values_right[i][1],
                fs_output.queried_values_right[i][2],
                fs_output.queried_values_right[i][3],
                fs_output.queried_values_right[i][4],
            ],
        ));

        let denominator_inverses_expected = &prepare_output.denominator_inverses_expected;

        let eval_left = fs_output.random_coeff.pow(6)
            * QM31::from(nominators[0].0[0] * denominator_inverses_expected[i][0][0])
            + fs_output.random_coeff.pow(5)
                * QM31::from(nominators[1].0[0] * denominator_inverses_expected[i][1][0])
            + fs_output.random_coeff.pow(4)
                * QM31::from(nominators[2].0[0] * denominator_inverses_expected[i][2][0])
            + (fs_output.random_coeff.pow(3) * QM31::from(nominators[3].0[0])
                + fs_output.random_coeff.pow(2) * QM31::from(nominators[3].0[1])
                + fs_output.random_coeff * QM31::from(nominators[3].0[2])
                + QM31::from(nominators[3].0[3]))
                * QM31::from(denominator_inverses_expected[i][3][0]);

        let eval_right = fs_output.random_coeff.pow(6)
            * QM31::from(nominators[0].1[0] * denominator_inverses_expected[i][0][1])
            + fs_output.random_coeff.pow(5)
                * QM31::from(nominators[1].1[0] * denominator_inverses_expected[i][1][1])
            + fs_output.random_coeff.pow(4)
                * QM31::from(nominators[2].1[0] * denominator_inverses_expected[i][2][1])
            + (fs_output.random_coeff.pow(3) * QM31::from(nominators[3].1[0])
                + fs_output.random_coeff.pow(2) * QM31::from(nominators[3].1[1])
                + fs_output.random_coeff * QM31::from(nominators[3].1[2])
                + QM31::from(nominators[3].1[3]))
                * QM31::from(denominator_inverses_expected[i][3][1]);

        let test_only_fri_answer = {
            let p = precomputed.circle_point;
            let py_inverse = p.y.inverse();

            let f_p = eval_left;
            let f_neg_p = eval_right;

            let (mut f0_px, mut f1_px) = (f_p, f_neg_p);
            ibutterfly(&mut f0_px, &mut f1_px, py_inverse);

            vec![f0_px, f1_px]
        };

        fold_results
            .push(fs_output.circle_poly_alpha * test_only_fri_answer[1] + test_only_fri_answer[0]);

        hints.push(PerQueryQuotientHint {
            precomputed_merkle_proofs: vec![precomputed.clone()],
            denominator_inverse_hints,
        });
    }

    (QuotientsOutput { fold_results }, hints)
}

#[derive(Default, Clone)]
/// Hint that repeats for each query.
pub struct PerQueryQuotientHint {
    /// Precomputed tree Merkle proofs.
    pub precomputed_merkle_proofs: Vec<PrecomputedMerkleTreeProof>,

    /// Denominator inverse hints.
    pub denominator_inverse_hints: Vec<DenominatorInverseHint>,
}

impl Pushable for PerQueryQuotientHint {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        for proof in self.precomputed_merkle_proofs.iter() {
            builder = proof.bitcoin_script_push(builder);
        }
        for hint in self.denominator_inverse_hints.iter() {
            builder = hint.bitcoin_script_push(builder);
        }
        builder
    }
}
