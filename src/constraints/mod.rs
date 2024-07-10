mod bitcoin_script;

use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;

/// Inverse of a CM31 element and its sibling.
#[derive(Debug, Clone)]
pub struct DenominatorInverseHint {
    /// The inverse of this point, which has only the imaginary part.
    pub inverse: CM31,
    /// The inverse of the sibling.
    pub sibling_inverse: CM31,
}

impl Pushable for DenominatorInverseHint {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self.inverse.bitcoin_script_push(builder);
        builder = self.sibling_inverse.bitcoin_script_push(builder);
        builder
    }
}

impl DenominatorInverseHint {
    /// Compute the hint for denominator inverse.
    pub fn new(e0: CirclePoint<QM31>, p: CirclePoint<M31>) -> Self {
        let res = fast_twin_pair_vanishing(e0, p);
        Self {
            inverse: res.0.inverse(),
            sibling_inverse: res.1.inverse(),
        }
    }
}

/// The prepared point on the circle curve over QM31, for pair vanishing.
///
/// Suitable for points that would be used to compute multiple pair vanishing, which is the case in
/// FRI where the same point is evaluated over different sample points.
#[derive(Debug)]
pub struct PreparedPairVanishing {
    /// The imaginary part of the x coordinate divided by the imaginary part of the y coordinate.
    pub x_imag_div_y_imag: CM31,
    /// The doubled cross term, `e0.x.1/e0.y.1 * e0.y.0 - e0.x.0`.
    pub cross_term: CM31,
}

impl From<CirclePoint<QM31>> for PreparedPairVanishing {
    fn from(e0: CirclePoint<QM31>) -> Self {
        let x_imag_div_y_imag = e0.x.1 * e0.y.1.inverse();
        Self {
            x_imag_div_y_imag,
            cross_term: x_imag_div_y_imag * e0.y.0 - e0.x.0,
        }
    }
}

impl Pushable for PreparedPairVanishing {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self.x_imag_div_y_imag.bitcoin_script_push(builder);
        builder = self.cross_term.bitcoin_script_push(builder);
        builder
    }
}

/// Hint for computing the prepared pair vanishing value.
#[derive(Debug)]
pub struct PreparedPairVanishingHint {
    /// The coefficient before -X.y, which is `Im(P.x) / Im(P.y)`.
    pub x_imag_div_y_imag: CM31,
}

impl From<CirclePoint<QM31>> for PreparedPairVanishingHint {
    fn from(e0: CirclePoint<QM31>) -> Self {
        let x_imag_div_y_imag = e0.x.1 * e0.y.1.inverse();
        Self { x_imag_div_y_imag }
    }
}

impl Pushable for PreparedPairVanishingHint {
    fn bitcoin_script_push(&self, builder: Builder) -> Builder {
        self.x_imag_div_y_imag.bitcoin_script_push(builder)
    }
}

/// Pair vanishing over e0, e0's conjugated point, and p that is over M31.
pub fn fast_pair_vanishing(e0: CirclePoint<QM31>, p: CirclePoint<M31>) -> CM31 {
    let e0 = PreparedPairVanishing::from(e0);
    fast_pair_vanishing_from_prepared(e0, p)
}

/// Pair vanishing over e0 and e0's conjugated point (in the prepared form) and p that is over M31.
pub fn fast_pair_vanishing_from_prepared(e0: PreparedPairVanishing, p: CirclePoint<M31>) -> CM31 {
    // The original algorithm check computes the area of the triangle formed by the
    // 3 points. This is done using the determinant of:
    // | p.x  p.y  1 |
    // | e0.x e0.y 1 |
    // | e1.x e1.y 1 |
    // divided by 2i and |e0.y|'s imaginary part.
    //
    // This is a polynomial of degree 1 in p.x and p.y, and thus it is a line.
    // It vanishes at e0 and e1.

    // We are now handling a special case where e1 = complex_conjugate(e0) and p.x, p.y are M31.

    p.x - e0.x_imag_div_y_imag * p.y + e0.cross_term
}

/// Pair vanishing over a circle point and its conjugated point as well.
pub fn fast_twin_pair_vanishing(e0: CirclePoint<QM31>, p: CirclePoint<M31>) -> (CM31, CM31) {
    let e0 = PreparedPairVanishing::from(e0);
    fast_twin_pair_vanishing_from_prepared(e0, p)
}

/// Pair vanishing over a circle point (in the prepared form) and its conjugated point as well.
pub fn fast_twin_pair_vanishing_from_prepared(
    e0: PreparedPairVanishing,
    p: CirclePoint<M31>,
) -> (CM31, CM31) {
    // Extending from `fast_pair_vanishing`, but it computes it for p and its conjugated point.

    let term13 = p.x + e0.cross_term;
    let term2 = e0.x_imag_div_y_imag * p.y;

    let first = term13 - term2;
    let second = term13 + term2;

    (first, second)
}

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

/// Hint for computing the column line coeffs, which is the inverse of the y coordinate of the sample point.
#[derive(Clone, Debug)]
pub struct ColumnLineCoeffsHint {
    /// The inverse of the y coordinate of the sample point.
    pub y_imag_inv: CM31,
}

impl From<CirclePoint<QM31>> for ColumnLineCoeffsHint {
    fn from(point: CirclePoint<QM31>) -> Self {
        Self {
            y_imag_inv: point.y.1.inverse(),
        }
    }
}

impl Pushable for ColumnLineCoeffsHint {
    fn bitcoin_script_push(&self, builder: Builder) -> Builder {
        self.y_imag_inv.bitcoin_script_push(builder)
    }
}

#[cfg(test)]
mod test {
    use crate::constraints::{fast_pair_vanishing, fast_twin_pair_vanishing, ColumnLineCoeffs};
    use crate::utils::get_rand_qm31;
    use num_traits::Zero;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::ops::Neg;
    use stwo_prover::core::circle::{CirclePoint, M31_CIRCLE_GEN, SECURE_FIELD_CIRCLE_ORDER};
    use stwo_prover::core::constraints::pair_vanishing;
    use stwo_prover::core::fields::cm31::CM31;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fields::{ComplexConjugate, Field, FieldExpOps};

    #[test]
    fn test_fast_pair_vanishing() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let e0 = CirclePoint::<QM31>::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
        let p = M31_CIRCLE_GEN.mul(prng.gen::<u128>());

        let left = pair_vanishing(e0, e0.complex_conjugate(), p.into_ef());
        let right = fast_pair_vanishing(e0, p);
        assert_eq!(left.0, CM31::zero());
        assert_eq!(left.1, right.double() * e0.y.1);
    }

    #[test]
    fn test_fast_twin_pair_vanishing() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let e0 = CirclePoint::<QM31>::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
        let p = M31_CIRCLE_GEN.mul(prng.gen::<u128>());
        let neg_p = p.neg();

        let left = (
            pair_vanishing(e0, e0.complex_conjugate(), p.into_ef()),
            pair_vanishing(e0, e0.complex_conjugate(), neg_p.into_ef()),
        );
        let right = fast_twin_pair_vanishing(e0, p);

        // The gap is `2 * e0.y.1`.
        assert_eq!(left.0 .0, CM31::zero());
        assert_eq!(left.0 .1, right.0.double() * e0.y.1);
        assert_eq!(left.1 .0, CM31::zero());
        assert_eq!(left.1 .1, right.1.double() * e0.y.1);
    }

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
