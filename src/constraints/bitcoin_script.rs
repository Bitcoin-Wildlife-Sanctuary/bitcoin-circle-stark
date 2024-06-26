use crate::{circle::CirclePointGadget, treepp::*};
use rust_bitcoin_m31::{
    cm31_add, cm31_copy, cm31_double, cm31_drop, cm31_dup, cm31_fromaltstack, cm31_mul,
    cm31_mul_m31, cm31_neg, cm31_over, cm31_rot, cm31_sub, cm31_swap, cm31_toaltstack, m31_add,
    qm31_add, qm31_mul_m31_by_constant, qm31_roll, qm31_swap,
};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::{
    circle::{CirclePoint, Coset},
    fields::qm31::QM31,
};

/// Gadget for constraints over the circle curve.
pub struct ConstraintsGadget;

impl ConstraintsGadget {
    /// Compute the parameters of `column_line_coeffs` without applying alpha.
    ///
    /// Input:
    /// - `p.y, f1(p), f2(p), ..., fn(p)`
    ///
    /// Output:
    /// - `c, (a1, b1), (a2, b2), (a3, b3), ..., (an, bn)`
    /// where all of them are cm31 (and it represents the imaginary part rather than the real part).
    /// where:
    /// - `ai = conjugate(fi(p)) - fi(p) = -2yi`, aka double-neg of the imaginary part (which is a cm31)
    /// - `bi = fi(p) * c - a * p.y
    ///       = fi(p) * (conjugate(p.y) - p.y) - (conjugate(fi(p)) - fi(p)) * p.y
    ///       = fi(p) * conjugate(p.y) - conjugate(fi(p)) * p.y
    ///       = (x + yi) * (u - vi) - (x - yi) * (u + vi)
    ///       = 2(yu - xv)i`, which is also cm31.
    /// - `c = conjugate(p.y) - p.y = -2vi`, aka double-neg of the imaginary part (which is a cm31)
    ///
    pub fn column_line_coeffs(num_columns: usize) -> Script {
        assert!(num_columns > 0);
        script! {
            // roll p.y
            { qm31_roll(num_columns) }

            // process each column
            for _ in 0..num_columns {
                qm31_swap
                // top of the stack:
                //   c: v cm31
                //   c: u cm31
                //   fn(p): y cm31
                //   fn(p): x cm31

                { cm31_copy(3) }

                cm31_mul cm31_toaltstack
                cm31_over cm31_over cm31_mul
                cm31_fromaltstack cm31_sub cm31_double
                cm31_toaltstack

                cm31_double cm31_neg cm31_toaltstack
            }

            // stack:
            //   c
            //
            // altstack:
            //   bn, an, ..., ..., b1, a1
            cm31_drop
            cm31_double cm31_neg

            for _ in 0..num_columns {
                cm31_fromaltstack
                cm31_fromaltstack
            }
        }
    }

    /// Evaluates a vanishing polynomial P : CirclePoint -> QM31 of the given coset
    ///
    /// input:
    ///  z.x (QM31)
    ///  z.y (QM31)
    ///
    /// output:
    ///  P(z)
    pub fn coset_vanishing(coset: Coset) -> Script {
        let shift =
            -coset.initial.into_ef::<QM31>() + coset.step_size.half().to_point().into_ef::<QM31>();

        script! {
            { shift.x }
            { shift.y }
            { CirclePointGadget::add_x_only() }
            for _ in 1..coset.log_size {
                { CirclePointGadget::double_x() }
            }
        }
    }

    /// Evaluates a polynomial P : CirclePoint -> QM31 that vanishes at excluded0 and excluded1
    ///
    /// Input:
    /// - z.x (QM31)
    /// - z.y (QM31)
    ///
    /// Output:
    /// - P(z)
    pub fn pair_vanishing_with_constant_m31_points(
        excluded0: CirclePoint<M31>,
        excluded1: CirclePoint<M31>,
    ) -> Script {
        script! {
            { qm31_mul_m31_by_constant((excluded1.x - excluded0.x).0) } // (excluded1.x - excluded0.x) * z.y

            qm31_swap
            { qm31_mul_m31_by_constant((excluded0.y - excluded1.y).0) } // (excluded0.y - excluded1.y) * z.x

            qm31_add
            { excluded0.x * excluded1.y - excluded0.y * excluded1.x }
            m31_add
            // (excluded0.y - excluded1.y) * z.x
            //    + (excluded1.x - excluded0.x) * z.y
            //    + (excluded0.x * excluded1.y - excluded0.y * excluded1.x)
        }
    }

    /// Evaluate a fast pair vanishing polynomial where exclude1 = complex_conjugate(exclude0) and
    /// z.x and z.y are both M31 elements.
    ///
    /// Input:
    /// - exclude0
    ///   * exclude0.x.1 (2 elements)
    ///   * exclude0.x.0 (2 elements)
    ///   * exclude0.y.1 (2 elements)
    ///   * exclude0.y.0 (2 elements)
    /// - z.x (1 element)
    /// - z.y (1 element)
    ///
    /// Output:
    /// - qm31
    ///
    pub fn fast_pair_vanishing() -> Script {
        script! {
            // copy exclude0.y.1
            5 OP_PICK 5 OP_PICK
            // copy z.x
            3 OP_ROLL
            cm31_mul_m31

            // copy exclude0.x.1
            10 OP_PICK 10 OP_PICK
            // copy z.y
            4 OP_ROLL
            cm31_mul_m31

            cm31_sub cm31_toaltstack

            cm31_toaltstack cm31_mul cm31_swap cm31_fromaltstack cm31_mul
            cm31_swap cm31_sub cm31_fromaltstack cm31_add cm31_double

            { 0 } { 0 }
        }
    }

    /// Evaluate a fast pair vanishing polynomial where exclude1 = complex_conjugate(exclude0) and
    /// z.x and z.y are both M31 elements.
    ///
    /// Input:
    /// - exclude0
    ///   * exclude0.x.1 (2 elements)
    ///   * exclude0.x.0 (2 elements)
    ///   * exclude0.y.1 (2 elements)
    ///   * exclude0.y.0 (2 elements)
    /// - z.x (1 element)
    /// - z.y (1 element)
    ///
    /// Output:
    /// - qm31 for z
    /// - qm31 for conjugated z
    ///
    pub fn fast_twin_pair_vanishing() -> Script {
        script! {
            // copy exclude0.y.1
            5 OP_PICK 5 OP_PICK
            // copy z.x
            3 OP_ROLL
            cm31_mul_m31 cm31_toaltstack

            // copy exclude0.x.1
            8 OP_PICK 8 OP_PICK
            // copy z.y
            2 OP_ROLL
            cm31_mul_m31 cm31_toaltstack

            // compute the cross term
            cm31_toaltstack cm31_mul cm31_swap cm31_fromaltstack cm31_mul
            cm31_swap cm31_sub

            // stack:
            // - exclude0.x.1 * exclude0.y.0 - exclude0.x.0 *  exclude0.y.1 (2 elements)
            //
            // altstack:
            // - e0.y.1 * p.x (2 elements)
            // - e0.x.1 * p.y (2 elements)

            cm31_fromaltstack cm31_fromaltstack cm31_rot cm31_add

            // stack:
            // - e0.x.1 * p.y (2 elements)
            // - term1 + term3 (2 elements)

            // stack:
            // - e0.x.1 * p.y (2 elements)
            // - term1 + term3 (2 elements)
            // - term1 + term3 (2 elements)

            cm31_dup { cm31_copy(2) } cm31_sub cm31_double cm31_toaltstack
            cm31_add cm31_double cm31_fromaltstack cm31_swap

            // stack:
            // - cm31 for z
            // - cm31 for conjugated z

            { 0 } { 0 }
            cm31_swap
            { 0 } { 0 }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::constraints::{fast_pair_vanishing, fast_twin_pair_vanishing};
    use crate::utils::get_rand_qm31;
    use crate::{
        constraints::ConstraintsGadget, tests_utils::report::report_bitcoin_script_size, treepp::*,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::{cm31_equalverify, qm31_equalverify};
    use std::ops::{Mul, Sub};
    use stwo_prover::core::circle::{
        CirclePoint, Coset, M31_CIRCLE_GEN, SECURE_FIELD_CIRCLE_ORDER,
    };
    use stwo_prover::core::constraints::{coset_vanishing, pair_vanishing};
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fields::ComplexConjugate;

    #[test]
    fn test_coset_vanishing() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for log_size in 5..10 {
            let coset = Coset::subgroup(log_size);
            let coset_vanishing_script = ConstraintsGadget::coset_vanishing(coset);
            println!(
                "Constraints.coset_vanishing(log_size={}) = {} bytes",
                log_size,
                coset_vanishing_script.len()
            );
            report_bitcoin_script_size(
                "Constraints",
                format!("coset_vanishing(log_size={})", log_size).as_str(),
                coset_vanishing_script.len(),
            );

            let z = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };

            let res = coset_vanishing(coset, z);

            let script = script! {
                { z.x }
                { z.y }
                { coset_vanishing_script.clone() }
                { res }
                qm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_pair_vanishing_with_constant_m31_points() {
        for seed in 0..20 {
            let mut prng = ChaCha20Rng::seed_from_u64(seed);

            let z = CirclePoint::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);

            let excluded0 = M31_CIRCLE_GEN.mul(prng.gen::<u128>());
            let excluded1 = M31_CIRCLE_GEN.mul(prng.gen::<u128>());

            let res = pair_vanishing(excluded0.into_ef(), excluded1.into_ef(), z);

            let pair_vanishing_script =
                ConstraintsGadget::pair_vanishing_with_constant_m31_points(excluded0, excluded1);
            if seed == 0 {
                report_bitcoin_script_size(
                    "Constraints",
                    "pair_vanishing",
                    pair_vanishing_script.len(),
                );
            }

            let script = script! {
                { z.x }
                { z.y }
                { pair_vanishing_script.clone() }
                { res }
                qm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_fast_pair_vanishing() {
        for seed in 0..20 {
            let mut prng = ChaCha20Rng::seed_from_u64(seed);

            let e0 = CirclePoint::<QM31>::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
            let p = M31_CIRCLE_GEN.mul(prng.gen::<u128>());

            let res = fast_pair_vanishing(e0, p);

            let pair_vanishing_script = ConstraintsGadget::fast_pair_vanishing();
            if seed == 0 {
                report_bitcoin_script_size(
                    "Constraints",
                    "fast_pair_vanishing",
                    pair_vanishing_script.len(),
                );
            }

            let script = script! {
                { e0 }
                { p.x }
                { p.y }
                { pair_vanishing_script.clone() }
                { res }
                qm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_fast_twin_pair_vanishing() {
        for seed in 0..20 {
            let mut prng = ChaCha20Rng::seed_from_u64(seed);

            let e0 = CirclePoint::<QM31>::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
            let p = M31_CIRCLE_GEN.mul(prng.gen::<u128>());

            let res = fast_twin_pair_vanishing(e0, p);

            let pair_vanishing_script = ConstraintsGadget::fast_twin_pair_vanishing();
            if seed == 0 {
                report_bitcoin_script_size(
                    "Constraints",
                    "fast_twin_pair_vanishing",
                    pair_vanishing_script.len(),
                );
            }

            let script = script! {
                { e0 }
                { p.x }
                { p.y }
                { pair_vanishing_script.clone() }
                { res.1 }
                qm31_equalverify
                { res.0 }
                qm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_column_line_coeffs() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for column_len in 1..=10 {
            let point = CirclePoint::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
            let mut values = vec![];
            for _ in 0..column_len {
                values.push(get_rand_qm31(&mut prng));
            }

            let column_line_coeffs_script = ConstraintsGadget::column_line_coeffs(column_len);

            report_bitcoin_script_size(
                "Constraints",
                format!("column_line_coeffs({})", column_len).as_str(),
                column_line_coeffs_script.len(),
            );

            let expected = {
                let mut res = vec![];
                for value in values.iter() {
                    let a = value.complex_conjugate().sub(*value);
                    let c = point.complex_conjugate().y - point.y;
                    let b = value.mul(c) - a * point.y;

                    res.push((a, b, c));
                }
                res
            };

            let script = script! {
                { point.y }
                for value in values.iter() {
                    { value }
                }
                { column_line_coeffs_script.clone() }
                for elems in expected.iter().rev() {
                    { elems.1.1 }
                    cm31_equalverify
                    { elems.0.1 }
                    cm31_equalverify
                }
                { expected[0].2.1 }
                cm31_equalverify
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
