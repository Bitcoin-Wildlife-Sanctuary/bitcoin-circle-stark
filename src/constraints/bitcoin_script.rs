use crate::{circle::CirclePointGadget, treepp::*};
use rust_bitcoin_m31::{
    cm31_add, cm31_double, cm31_fromaltstack, cm31_mul, cm31_mul_m31, cm31_sub, cm31_swap,
    cm31_toaltstack, m31_add, m31_double, m31_neg, push_m31_zero, qm31_add, qm31_copy, qm31_drop, qm31_dup, qm31_from_bottom,
    qm31_mul, qm31_mul_m31_by_constant, qm31_roll, qm31_sub, qm31_swap
};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::{
    circle::{CirclePoint, Coset},
    fields::qm31::QM31,
};

/// Gadget for constraints over the circle curve.
pub struct ConstraintsGadget;

impl ConstraintsGadget {
    /// clear parameters of column_line_coeffs
    /// stack input:
    /// [alpha_0, alpha_1, ..., alpha_{n - 1}, p1y, f1(p1), f2(p1), ..., fn(p1), p2y, f1(p2), f2(p2), ..., fn(p2), ..., pmy, f1(pm), f2(pm), ..., fn(pm)]
    ///
    /// output:
    /// [(`alpha_0 * a`, `alpha_0 * b`, `alpha_0 * c`), (`alpha_1 * a`, `alpha_1 * b`, `alpha_1 * c`), ...]
    pub fn column_line_coeffs(num_points: usize, num_columns: usize) -> Script {
        script! {
            for i in 0..num_points {
                for j in 0..num_columns {
                    // index of sample.value: (num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j)
                    // index of sample.point: (num_points - 1 - i) * (num_columns + 1) + num_columns
                    // index of alpha: (num_points - i) * (num_columns + 1)

                    // let a = sample.value.complex_conjugate() - sample.value;
                    // copy imagic part of sample value, 3 is imagic offset
                    { ((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + (i * num_columns + j) * 3) * 4 + 3 } OP_PICK
                    m31_double
                    m31_neg
                    { ((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + (i * num_columns + j) * 3) * 4 + 3 } OP_PICK
                    m31_double
                    m31_neg
                    push_m31_zero
                    push_m31_zero
                    // [..., a]
                    // copy alpha_j, 1 denotes the incremental a
                    { qm31_copy((num_points - i) * (num_columns + 1) - j + (num_columns - 1 - j) + (i * num_columns + j) * 3 + 1) }
                    qm31_mul
                    // [..., alpha_j * a]

                    // let c = sample.point.complex_conjugate().y - sample.point.y;
                    // copy imagic part of sample point y, 3 denotes imagic offset, 4 denotes the incremental a
                    { ((num_points - 1 - i) * (num_columns + 1) + (num_columns - j) + (i * num_columns + j) * 3 + 1) * 4 + 3} OP_PICK
                    m31_double
                    m31_neg
                    { ((num_points - 1 - i) * (num_columns + 1) + (num_columns - j) + (i * num_columns + j) * 3 + 1) * 4 + 3 } OP_PICK
                    m31_double
                    m31_neg
                    push_m31_zero
                    push_m31_zero
                    // [..., alpha_j * a, c]
                    // copy alpha_j, 2 denotes the incremental a, c
                    { qm31_copy((num_points - i) * (num_columns + 1) - j + (num_columns - 1 - j) + (i * num_columns + j) * 3 + 2) }
                    qm31_mul
                    // [..., alpha_j * a, alpha_j * c]

                    // let b = sample.value * c - a * sample.point.y;
                    // copy sample value, 2 denote the incremental a, c
                    qm31_dup
                    { qm31_roll((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + (i * num_columns + j) * 3 + 3) }
                    qm31_mul
                    if j == num_columns - 1 {
                        { qm31_roll((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + (i * num_columns + j) * 3 + 3) }
                    } else {
                        { qm31_copy((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + (i * num_columns + j) * 3 + 3) }
                    }
                    { qm31_copy(3) }
                    qm31_mul
                    qm31_sub
                    // [..., alpha_j * a, alpha_j * c, alpha_j * b]

                    qm31_swap
                    // [..., alpha_j * a, alpha_j * b, alpha_j * c]
                }
            }
            // drop all alphas
            for _ in 0..num_columns {
                qm31_from_bottom
                qm31_drop
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
            // copy p.x
            3 OP_ROLL
            cm31_mul_m31

            // copy exclude0.x.1
            10 OP_PICK 10 OP_PICK
            // copy p.y
            4 OP_ROLL
            cm31_mul_m31

            cm31_sub cm31_toaltstack

            cm31_toaltstack cm31_mul cm31_swap cm31_fromaltstack cm31_mul
            cm31_swap cm31_sub cm31_fromaltstack cm31_add cm31_double

            { 0 } { 0 }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::constraints::fast_pair_vanishing;
    use crate::utils::get_rand_qm31;
    use crate::{
        constraints::ConstraintsGadget, tests_utils::report::report_bitcoin_script_size, treepp::*,
    };
    use itertools::Itertools;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::{qm31_equalverify, qm31_roll, qm31_rot};
    use stwo_prover::core::backend::cpu::quotients::column_line_coeffs;
    use stwo_prover::core::circle::SECURE_FIELD_CIRCLE_GEN;
    use stwo_prover::core::constraints::{coset_vanishing, pair_vanishing};
    use stwo_prover::core::fields::FieldExpOps;
    use stwo_prover::core::pcs::quotients::ColumnSampleBatch;
    use stwo_prover::core::circle::{
        CirclePoint, Coset, M31_CIRCLE_GEN, SECURE_FIELD_CIRCLE_ORDER,
    };
    use stwo_prover::core::fields::qm31::QM31;
    
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
    fn test_column_line_coeffs() {
        let num_points = 2_usize;
        let num_columns = 4_usize;
        let generator = SECURE_FIELD_CIRCLE_GEN;

        let mut prng = ChaCha20Rng::seed_from_u64(6u64);
        let samples = (0..num_points)
            .map(|_| {
                let scalar: u32 = prng.gen();
                let sample_point = generator.mul(scalar as u128);
                let column_values = (0..num_columns)
                    .map(|i| (i, get_rand_qm31(&mut prng)))
                    .collect_vec();
                ColumnSampleBatch {
                    point: sample_point,
                    columns_and_values: column_values,
                }
            })
            .collect_vec();

        let random_coeff = get_rand_qm31(&mut prng);
        let hints = column_line_coeffs(&samples, random_coeff);
        let alphas = (0..num_columns)
            .map(|i| random_coeff.pow(i as u128 + 1))
            .collect_vec();
        let column_line_coeffs_script =
            ConstraintsGadget::column_line_coeffs(num_points, num_columns);
        report_bitcoin_script_size(
            "Constraints",
            "pair_vanishing",
            column_line_coeffs_script.len(),
        );
        let script = script! {
            // push alpha_0, alpha_1, alpha_2, alpha_3, ...
            for j in 0..num_columns {
                { alphas[j] }
            }
            // push p1_y, f1(p1), f2(p1), ..., fn(p1), p2_y, f1(p2), ..., fn(p2), ..., pm_y, fn(pm)
            for i in 0..num_points {
                { samples[i].point.y }
                for j in 0..num_columns {
                    { samples[i].columns_and_values[j].1 }
                }
            }
            { column_line_coeffs_script.clone() }
            for i in 0..num_points {
                for j in 0..num_columns {
                    { hints[i][j].0 }
                    { hints[i][j].1 }
                    { hints[i][j].2 }

                    { qm31_roll((num_points - 1 - i) * (num_columns * 3) + (num_columns - 1 - j) * 3 + 3 + 2) }
                    { qm31_roll(3) }
                    qm31_equalverify
                    { qm31_roll((num_points - 1 - i) * (num_columns * 3) + (num_columns - 1 - j) * 3 + 2 + 1) }
                    qm31_rot
                    qm31_equalverify
                    { qm31_roll((num_points - 1 - i) * (num_columns * 3) + (num_columns - 1 - j) * 3 + 1) }
                    qm31_equalverify
                }
            }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
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
}
