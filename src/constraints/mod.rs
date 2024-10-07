use crate::treepp::pushable::{Builder, Pushable};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;

/// The column line coefficients.
#[derive(Clone, Debug)]
pub struct ColumnLineCoeffs {
    /// The coefficient before `-X.y`, which is `Im(f(P)) / Im(P.y)`.
    pub fp_imag_div_y_imag: Vec<CM31>,
    /// The cross term, which is `Im(f(P)) / Im(P.y) * Re(P.y) - Re(f(P)) `.
    pub cross_term: Vec<CM31>,
}

impl ColumnLineCoeffs {
    /// Compute the column line coeffs from values and the sample point.
    pub fn from_values_and_point(values: &[QM31], point: CirclePoint<QM31>) -> Self {
        let mut fp_imag_div_y_imag = vec![];
        let mut cross_term = vec![];

        let y_imag_inverse = point.y.1.inverse();

        for value in values.iter() {
            let tmp = value.1 * y_imag_inverse;

            fp_imag_div_y_imag.push(tmp);
            cross_term.push(value.0 - point.y.0 * tmp);
        }

        Self {
            fp_imag_div_y_imag,
            cross_term,
        }
    }

    /// Apply the column line coeffs onto a point and its evaluation.
    pub fn apply_twin(
        &self,
        point: CirclePoint<M31>,
        evals_left: &[M31],
        evals_right: &[M31],
    ) -> (Vec<CM31>, Vec<CM31>) {
        assert_eq!(evals_left.len(), self.fp_imag_div_y_imag.len());
        assert_eq!(evals_left.len(), self.cross_term.len());
        assert_eq!(evals_left.len(), evals_right.len());

        let mut res_left = vec![];
        let mut res_right = vec![];
        for (((&fp_imag_div_y_imag, &cross_term), &eval_left), &eval_right) in self
            .fp_imag_div_y_imag
            .iter()
            .zip(self.cross_term.iter())
            .zip(evals_left.iter())
            .zip(evals_right.iter())
        {
            let mut tmp = fp_imag_div_y_imag;
            tmp *= point.y;
            res_left.push(eval_left - (cross_term + tmp));
            res_right.push(eval_right - (cross_term - tmp));
        }
        (res_left, res_right)
    }
}

impl Pushable for ColumnLineCoeffs {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        for (fp_imag_div_y_imag, cross_term) in
            self.fp_imag_div_y_imag.iter().zip(self.cross_term.iter())
        {
            builder = fp_imag_div_y_imag.bitcoin_script_push(builder);
            builder = cross_term.bitcoin_script_push(builder);
        }
        builder
    }
}

#[cfg(test)]
mod test {
    use crate::constraints::ColumnLineCoeffs;
    use crate::utils::get_rand_qm31;
    use num_traits::Zero;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_prover::core::circle::{CirclePoint, SECURE_FIELD_CIRCLE_ORDER};
    use stwo_prover::core::fields::cm31::CM31;
    use stwo_prover::core::fields::{ComplexConjugate, FieldExpOps};

    #[test]
    fn test_fast_column_line_coeffs() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let point = CirclePoint::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
        let value = get_rand_qm31(&mut prng);

        let expected = {
            let a = value.complex_conjugate() - value;
            let c = point.complex_conjugate().y - point.y;
            let b = value * c - a * point.y;

            (a * c.inverse(), b * c.inverse())
        };
        assert_eq!(expected.0 .1, CM31::zero());
        assert_eq!(expected.1 .1, CM31::zero());

        let result = ColumnLineCoeffs::from_values_and_point(&[value], point);

        assert_eq!(expected.0 .0, result.fp_imag_div_y_imag[0]);
        assert_eq!(expected.1 .0, result.cross_term[0]);
    }
}
