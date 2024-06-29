mod bitcoin_script;

use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;
use num_traits::Zero;
use std::ops::Neg;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fields::{Field, FieldExpOps};

/// The inverse of j, which is `(2 - i) / 5`.
pub const INVERSE_OF_J: CM31 = CM31::from_u32_unchecked(1717986918, 1288490188);

/// Inverse of a QM31 element of the form a + bj where a = 0 (i.e., only having the imaginary part)
///
/// Note that `j^-1 = [(2 - i) / 5]j` because:
///   `j^2 [(2 - i) / 5] = (2 + i) (2 - i) / 5 = 1`
///
/// Therefore, the inverse of `bj` is `b^{-1} * [(2 - i) / 5] j`, which also only has the imaginary part.
///
/// To verify, note that `b * (b^{-1}) * [(2 - i) / 5] = (2 - i) / 5`.
#[derive(Debug, Clone)]
pub struct DenominatorInverseHint {
    /// The inverse of this point, which has only the imaginary part.
    pub inverse: CM31,
    /// The inverse of the sibling.
    pub sibling_inverse: CM31,
}

impl Pushable for &DenominatorInverseHint {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        builder = self.inverse.bitcoin_script_push(builder);
        builder = self.sibling_inverse.bitcoin_script_push(builder);
        builder
    }
}

impl Pushable for DenominatorInverseHint {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        (&self).bitcoin_script_push(builder)
    }
}

impl DenominatorInverseHint {
    /// Compute the hint for denominator inverse.
    pub fn new(e0: CirclePoint<QM31>, p: CirclePoint<M31>) -> Self {
        let res = fast_twin_pair_vanishing(e0, p);
        Self {
            inverse: res.0.inverse().1,
            sibling_inverse: res.1.inverse().1,
        }
    }
}

/// The prepared point on the circle curve over QM31, for pair vanishing.
///
/// Suitable for points that would be used to compute multiple pair vanishing, which is the case in
/// FRI where the same point is evaluated over different sample points.
pub struct PreparedPairVanishing {
    /// The doubled imaginary part of the x coordinate.
    pub x_imag_dbl: CM31,
    /// The doubled imaginary part of the y coordinate.
    pub y_imag_dbl: CM31,
    /// The doubled cross term, `e0.x.1 * e0.y.0 - e0.x.0 * e0.y.1`.
    pub cross_term_dbl: CM31,
}

impl From<CirclePoint<QM31>> for PreparedPairVanishing {
    fn from(e0: CirclePoint<QM31>) -> Self {
        Self {
            x_imag_dbl: e0.x.1.double(),
            y_imag_dbl: e0.y.1.double(),
            cross_term_dbl: (e0.x.1 * e0.y.0 - e0.x.0 * e0.y.1).double(),
        }
    }
}

impl Pushable for &PreparedPairVanishing {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        builder = self.x_imag_dbl.bitcoin_script_push(builder);
        builder = self.y_imag_dbl.bitcoin_script_push(builder);
        builder = self.cross_term_dbl.bitcoin_script_push(builder);
        builder
    }
}

impl Pushable for PreparedPairVanishing {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        (&self).bitcoin_script_push(builder)
    }
}

/// Pair vanishing over e0, e0's conjugated point, and p that is over M31.
pub fn fast_pair_vanishing(e0: CirclePoint<QM31>, p: CirclePoint<M31>) -> QM31 {
    let e0 = PreparedPairVanishing::from(e0);
    fast_pair_vanishing_from_prepared(e0, p)
}

/// Pair vanishing over e0 and e0's conjugated point (in the prepared form) and p that is over M31.
pub fn fast_pair_vanishing_from_prepared(e0: PreparedPairVanishing, p: CirclePoint<M31>) -> QM31 {
    // The original algorithm check computes the area of the triangle formed by the
    // 3 points. This is done using the determinant of:
    // | p.x  p.y  1 |
    // | e0.x e0.y 1 |
    // | e1.x e1.y 1 |
    // This is a polynomial of degree 1 in p.x and p.y, and thus it is a line.
    // It vanishes at e0 and e1.

    // We are now handling a special case where e1 = complex_conjugate(e0) and p.x, p.y are M31.

    let term1 = e0.y_imag_dbl * p.x;
    let term2 = e0.x_imag_dbl * p.y;
    let term3 = e0.cross_term_dbl;

    QM31(CM31::zero(), term1 - term2 + term3)
}

/// Pair vanishing over a circle point and its conjugated point as well.
pub fn fast_twin_pair_vanishing(e0: CirclePoint<QM31>, p: CirclePoint<M31>) -> (QM31, QM31) {
    let e0 = PreparedPairVanishing::from(e0);
    fast_twin_pair_vanishing_from_prepared(e0, p)
}

/// Pair vanishing over a circle point (in the prepared form) and its conjugated point as well.
pub fn fast_twin_pair_vanishing_from_prepared(
    e0: PreparedPairVanishing,
    p: CirclePoint<M31>,
) -> (QM31, QM31) {
    // Extending from `fast_pair_vanishing`, but it computes it for p and its conjugated point.

    let term13 = e0.y_imag_dbl * p.x + e0.cross_term_dbl;
    let term2 = e0.x_imag_dbl * p.y;

    let first = term13 - term2;
    let second = term13 + term2;

    (QM31(CM31::zero(), first), QM31(CM31::zero(), second))
}

/// Compute column line coeffs without involving alpha and obtain the imaginary part of the result.
pub fn fast_column_line_coeffs(point_y: &SecureField, value: &SecureField) -> (CM31, CM31, CM31) {
    // - `ai = conjugate(fi(p)) - fi(p) = -2yi`, aka double-neg of the imaginary part (which is a cm31)
    // - `bi = fi(p) * c - a * p.y
    //       = fi(p) * (conjugate(p.y) - p.y) - (conjugate(fi(p)) - fi(p)) * p.y
    //       = fi(p) * conjugate(p.y) - conjugate(fi(p)) * p.y
    //       = (x + yi) * (u - vi) - (x - yi) * (u + vi)
    //       = 2(yu - xv)i`, which is also cm31.
    // - `c = conjugate(p.y) - p.y = -2vi`, aka double-neg of the imaginary part (which is a cm31)

    let a = value.1.double().neg();
    let c = point_y.1.double().neg();

    let b = (value.1 * point_y.0 - value.0 * point_y.1).double();

    (a, b, c)
}

#[cfg(test)]
mod test {
    use crate::constraints::{
        fast_column_line_coeffs, fast_pair_vanishing, fast_twin_pair_vanishing, INVERSE_OF_J,
    };
    use crate::utils::get_rand_qm31;
    use num_traits::{One, Zero};
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::ops::Neg;
    use stwo_prover::core::circle::{CirclePoint, M31_CIRCLE_GEN, SECURE_FIELD_CIRCLE_ORDER};
    use stwo_prover::core::constraints::pair_vanishing;
    use stwo_prover::core::fields::cm31::CM31;
    use stwo_prover::core::fields::m31::M31;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fields::{ComplexConjugate, FieldExpOps};

    #[test]
    fn test_fast_pair_vanishing() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let e0 = CirclePoint::<QM31>::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
        let p = M31_CIRCLE_GEN.mul(prng.gen::<u128>());

        let left = pair_vanishing(e0, e0.complex_conjugate(), p.into_ef());
        let right = fast_pair_vanishing(e0, p);
        assert_eq!(left, right);
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
        assert_eq!(left, right);
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

            (a, b, c)
        };

        let result = fast_column_line_coeffs(&point.y, &value);

        assert_eq!(expected.0, QM31(CM31::zero(), result.0));
        assert_eq!(expected.1, QM31(CM31::zero(), result.1));
        assert_eq!(expected.2, QM31(CM31::zero(), result.2));
    }

    #[test]
    fn test_imag_only_inverse() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let j_inverse = QM31(CM31::zero(), CM31::one()).inverse();
        assert_eq!(j_inverse.0, CM31::zero());
        assert_eq!(
            j_inverse.1 .0,
            M31::from_u32_unchecked(2) * M31::from_u32_unchecked(5).inverse()
        );
        assert_eq!(j_inverse.1 .1, M31::from_u32_unchecked(5).inverse().neg());

        assert_eq!(j_inverse.1, INVERSE_OF_J);

        let qm31 = QM31(
            CM31::zero(),
            CM31::from_m31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
        );

        let qm31_inverse = qm31.inverse();

        assert_eq!(qm31_inverse.0, CM31::zero());
        assert_eq!(qm31_inverse.1, j_inverse.1 * qm31.1.inverse());
    }
}
