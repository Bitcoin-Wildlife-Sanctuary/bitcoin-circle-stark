mod bitcoin_script;

pub use bitcoin_script::*;
use num_traits::Zero;
use std::ops::Neg;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fields::Field;

/// Pair vanishing over e0, e0's conjugated point, and p that is over M31.
pub fn fast_pair_vanishing(e0: CirclePoint<QM31>, p: CirclePoint<M31>) -> QM31 {
    // The original algorithm check computes the area of the triangle formed by the
    // 3 points. This is done using the determinant of:
    // | p.x  p.y  1 |
    // | e0.x e0.y 1 |
    // | e1.x e1.y 1 |
    // This is a polynomial of degree 1 in p.x and p.y, and thus it is a line.
    // It vanishes at e0 and e1.

    // We are now handling a special case where e1 = complex_conjugate(e0) and p.x, p.y are M31.

    let term1 = e0.y.1 * p.x;
    let term2 = e0.x.1 * p.y;
    let term3 = e0.x.1 * e0.y.0 - e0.x.0 * e0.y.1;

    QM31(CM31::zero(), (term1 - term2 + term3).double())
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
    use crate::constraints::{fast_column_line_coeffs, fast_pair_vanishing};
    use crate::utils::get_rand_qm31;
    use num_traits::Zero;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_prover::core::circle::{CirclePoint, M31_CIRCLE_GEN, SECURE_FIELD_CIRCLE_ORDER};
    use stwo_prover::core::constraints::pair_vanishing;
    use stwo_prover::core::fields::cm31::CM31;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fields::ComplexConjugate;

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
}
