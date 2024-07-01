use crate::{circle::CirclePointGadget, treepp::*};
use rust_bitcoin_m31::{
    cm31_add, cm31_copy, cm31_dup, cm31_equalverify, cm31_from_bottom, cm31_fromaltstack, cm31_mul,
    cm31_mul_m31, cm31_over, cm31_roll, cm31_rot, cm31_sub, cm31_swap, cm31_toaltstack, m31_add,
    push_cm31_one, qm31_add, qm31_drop, qm31_mul_m31_by_constant, qm31_roll, qm31_swap,
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
    /// Hint:
    /// - `y_imag_inv`
    ///
    /// Input:
    /// - `p.y, f1(p), f2(p), ..., fn(p)`, all of which are QM31
    ///
    /// Output:
    /// - `(a1, b1), (a2, b2), (a3, b3), ..., (an, bn)`
    /// where all of them are cm31.
    /// - `ai = Im(f(P)) / Im(p.y)`
    /// - `bi = Re(f(P)) - Im(f(P))/ Im(p.y) Re(p.y)`
    ///
    pub fn column_line_coeffs_with_hint(num_columns: usize) -> Script {
        assert!(num_columns > 0);
        script! {
            // compute 1 / Im(p.y) first

            // roll p.y
            { qm31_roll(num_columns) }
            cm31_swap

            // stack:
            // - f1(p), f2(p), ..., fn(p)
            // - p.y.0, p.y.1

            cm31_from_bottom
            cm31_dup cm31_rot
            cm31_mul push_cm31_one cm31_equalverify

            // stack:
            // - f1(p), f2(p), ..., fn(p)
            // - p.y.0, y_imag_inv

            // process each column
            for _ in 0..num_columns {
                // pull the f(p)
                { qm31_roll(num_columns) } // treating (p.y.0, y_imag_inv) as a qm31

                // local stack:
                // - p.y.0
                // - y_imag_inv
                // - f1(p).1
                // - f1(p).0

                cm31_toaltstack
                cm31_over
                cm31_mul

                { cm31_copy(2) }
                cm31_over
                cm31_mul

                cm31_fromaltstack
                cm31_swap cm31_sub

                qm31_swap
            }

            qm31_drop
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

    /// Prepare for pair vanishing.
    ///
    /// Hint:
    /// - x_imag_div_y_imag
    ///
    /// Input:
    /// - exclude0
    ///   * exclude0.x.1 (2 elements)
    ///   * exclude0.x.0 (2 elements)
    ///   * exclude0.y.1 (2 elements)
    ///   * exclude0.y.0 (2 elements)
    ///
    /// Output:
    /// - x_imag_div_y_imag (2 elements)
    /// - cross_term (2 elements)
    pub fn prepare_pair_vanishing_with_hint() -> Script {
        script! {
            // pull exclude0.x.1
            { cm31_roll(3) }

            // pull exclude0.y.1
            { cm31_roll(2) }

            // pull x_imag_div_y_imag
            cm31_from_bottom
            cm31_dup cm31_toaltstack

            // check x_imag_div_y_imag * exclude0.y.1 = exclude0.x.1
            cm31_mul
            cm31_equalverify

            // recover x_imag_div_y_imag
            cm31_fromaltstack

            // stack:
            // - exclude0.x.0
            // - exclude0.y.0
            // - x_imag_div_y_imag

            cm31_dup cm31_rot cm31_mul
            cm31_rot cm31_sub
        }
    }

    /// Evaluate a fast pair vanishing polynomial where exclude1 = complex_conjugate(exclude0) and
    /// z.x and z.y are both M31 elements.
    ///
    /// Input:
    /// - x_imag_div_y_imag (2 elements)
    /// - cross_term (2 elements)
    /// - z.x (1 element)
    /// - z.y (1 element)
    ///
    /// Output:
    /// - cm31 = z.x - z.y * x_imag_div_y_imag + cross_term
    ///
    pub fn fast_pair_vanishing_from_prepared() -> Script {
        script! {
            OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
            cm31_swap OP_FROMALTSTACK

            // stack:
            // - cross_term
            // - x_imag_div_y_imag
            // - z.y
            //
            // altstack:
            // - z.x

            cm31_mul_m31
            cm31_sub

            // stack:
            // - cross_term - z.y * x_imag_div_y_imag
            //
            // altstack:
            // - z.x

            OP_FROMALTSTACK
            m31_add
        }
    }

    /// Evaluate a fast pair vanishing polynomial where exclude1 = complex_conjugate(exclude0) and
    /// z.x and z.y are both M31 elements.
    ///
    /// Input:
    /// - x_imag_div_y_imag (2 elements)
    /// - cross_term (2 elements)
    /// - z.x (1 element)
    /// - z.y (1 element)
    ///
    /// Output:
    /// - cm31 for z
    /// - cm31 for conjugated z
    ///
    pub fn fast_twin_pair_vanishing_from_prepared() -> Script {
        script! {
            OP_TOALTSTACK
            m31_add // add z.x to cross_term

            cm31_swap
            OP_FROMALTSTACK
            cm31_mul_m31 // compute x_imag_div_y_imag * z.y

            // stack:
            // - cross_term + z.x
            // - x_imag_div_y_imag * z.y

            cm31_over cm31_over
            cm31_add cm31_toaltstack
            cm31_sub cm31_fromaltstack
        }
    }

    /// Evaluate a fast pair vanishing polynomial where exclude1 = complex_conjugate(exclude0) and
    /// z.x and z.y are both M31 elements.
    ///
    /// Hint:
    /// - inverse cm31 for z
    /// - inverse cm31 for conjugated z
    ///
    /// Input:
    /// - x_imag_div_y_imag (2 elements)
    /// - cross_term (2 elements)
    /// - z.x (1 element)
    /// - z.y (1 element)
    ///
    /// Output:
    /// - inverse cm31 for z
    /// - inverse cm31 for conjugated z
    ///
    pub fn denominator_inverse_from_prepared() -> Script {
        script! {
            { Self::fast_twin_pair_vanishing_from_prepared() }
            cm31_toaltstack
            cm31_from_bottom
            cm31_swap
            cm31_over
            cm31_mul
            push_cm31_one
            cm31_equalverify

            cm31_fromaltstack
            cm31_from_bottom
            cm31_swap cm31_over
            cm31_mul
            push_cm31_one
            cm31_equalverify
        }
    }
}

#[cfg(test)]
mod test {
    use crate::constraints::{
        fast_pair_vanishing, fast_twin_pair_vanishing, ColumnLineCoeffs, ColumnLineCoeffsHint,
        DenominatorInverseHint, PreparedPairVanishing, PreparedPairVanishingHint,
    };
    use crate::utils::get_rand_qm31;
    use crate::{
        constraints::ConstraintsGadget, tests_utils::report::report_bitcoin_script_size, treepp::*,
    };
    use bitcoin_scriptexec::execute_script_with_witness;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::{cm31_equalverify, qm31_equalverify};
    use stwo_prover::core::circle::{
        CirclePoint, Coset, M31_CIRCLE_GEN, SECURE_FIELD_CIRCLE_ORDER,
    };
    use stwo_prover::core::constraints::{coset_vanishing, pair_vanishing};
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fields::FieldExpOps;

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
    fn test_fast_pair_vanishing_from_prepared() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let e0 = CirclePoint::<QM31>::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
            let p = M31_CIRCLE_GEN.mul(prng.gen::<u128>());

            let res = fast_pair_vanishing(e0, p);
            let h = PreparedPairVanishingHint::from(e0);

            let script = script! {
                { h }
                { e0 }
                { ConstraintsGadget::prepare_pair_vanishing_with_hint() }
                { p.x }
                { p.y }
                { ConstraintsGadget::fast_pair_vanishing_from_prepared() }
                { res }
                cm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_fast_twin_pair_vanishing_from_prepared() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let e0 = CirclePoint::<QM31>::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
            let p = M31_CIRCLE_GEN.mul(prng.gen::<u128>());

            let res = fast_twin_pair_vanishing(e0, p);
            let h = PreparedPairVanishingHint::from(e0);

            let script = script! {
                { h }
                { e0 }
                { ConstraintsGadget::prepare_pair_vanishing_with_hint() }
                { p.x }
                { p.y }
                { ConstraintsGadget::fast_twin_pair_vanishing_from_prepared() }
                { res.1 }
                cm31_equalverify
                { res.0 }
                cm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_denominator_inverse_from_prepared() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let e0 = CirclePoint::<QM31>::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);
            let p = M31_CIRCLE_GEN.mul(prng.gen::<u128>());

            let prepared_e0 = PreparedPairVanishing::from(e0);

            let res = fast_twin_pair_vanishing(e0, p);

            let inverse = (res.0.inverse(), res.1.inverse());

            let hint = DenominatorInverseHint::new(e0, p);

            let denominator_inverse_script = ConstraintsGadget::denominator_inverse_from_prepared();

            let script = script! {
                { prepared_e0 }
                { p.x }
                { p.y }
                { denominator_inverse_script.clone() }
                { inverse.1 }
                cm31_equalverify
                { inverse.0 }
                cm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script_with_witness(
                script,
                convert_to_witness(script! { { hint }}).unwrap(),
            );
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_prepare_pair_vanishing() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let e0 = CirclePoint::<QM31>::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);

            let res = PreparedPairVanishing::from(e0);
            let h = PreparedPairVanishingHint::from(e0);

            let prepare_script = ConstraintsGadget::prepare_pair_vanishing_with_hint();

            let script = script! {
                { h }
                { e0 }
                { prepare_script.clone() }
                { res.cross_term }
                cm31_equalverify
                { res.x_imag_div_y_imag }
                cm31_equalverify
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

            let h = ColumnLineCoeffsHint::from(point);

            let column_line_coeffs_script =
                ConstraintsGadget::column_line_coeffs_with_hint(column_len);

            report_bitcoin_script_size(
                "Constraints",
                format!("column_line_coeffs({})", column_len).as_str(),
                column_line_coeffs_script.len(),
            );

            let expected = ColumnLineCoeffs::from_values_and_point(&values, point);

            let script = script! {
                { h }
                { point.y }
                for value in values.iter() {
                    { value }
                }
                { column_line_coeffs_script.clone() }
                for (fp_imag_div_y_imag, cross_term) in expected.fp_imag_div_y_imag.iter().zip(expected.cross_term.iter()).rev() {
                    { cross_term }
                    cm31_equalverify
                    { fp_imag_div_y_imag }
                    cm31_equalverify
                }
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
