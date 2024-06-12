use crate::{circle::CirclePointGadget, treepp::*};
use rust_bitcoin_m31::{
    m31_double, m31_neg, push_m31_zero, push_qm31_one, qm31_add, qm31_complex_conjugate, qm31_copy,
    qm31_drop, qm31_dup, qm31_from_bottom, qm31_mul, qm31_over, qm31_roll, qm31_sub, qm31_swap,
};
use stwo_prover::core::pcs::quotients::ColumnSampleBatch;
use stwo_prover::core::{
    circle::{CirclePoint, Coset},
    fields::qm31::{SecureField, QM31},
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
    pub fn column_line_coeffs_new(num_points: usize, num_columns: usize) -> Script {
        script! {
            for i in 0..num_points {
                for j in 0..num_columns {
                    // index of sample.value: (num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j)
                    // index of sample.point: (num_points - 1 - i) * (num_columns + 1) + num_columns
                    // index of alpha: (num_points - i) * (num_columns + 1)

                    // let a = sample.value.complex_conjugate() - sample.value;
                    // copy imagic part of sample value, 3 is imagic offset
                    { ((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + j * 3) * 4 + 3 } OP_PICK
                    m31_double
                    m31_neg
                    { ((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + j * 3) * 4 + 3 } OP_PICK
                    m31_double
                    m31_neg
                    push_m31_zero
                    push_m31_zero
                    // [..., a]
                    // copy alpha_j, 1 denotes the incremental a
                    { qm31_copy((num_points - i) * (num_columns + 1) + (num_columns - 1 - j) + j * 3 + 1) }
                    qm31_mul
                    // [..., alpha_j * a]

                    // let c = sample.point.complex_conjugate().y - sample.point.y;
                    // copy imagic part of sample point y, 3 denotes imagic offset, 4 denotes the incremental a
                    { ((num_points - 1 - i) * (num_columns + 1) + (num_columns - j) + j * 3 + 1) * 4 + 3} OP_PICK
                    m31_double
                    m31_neg
                    { ((num_points - 1 - i) * (num_columns + 1) + (num_columns - j) + j * 3 + 1) * 4 + 3 } OP_PICK
                    m31_double
                    m31_neg
                    push_m31_zero
                    push_m31_zero
                    // [..., alpha_j * a, c]
                    // copy alpha_j, 2 denotes the incremental a, c
                    { qm31_copy((num_points - i) * (num_columns + 1) + (num_columns - 1 - j) + j * 3 + 2) }
                    qm31_mul
                    // [..., alpha_j * a, alpha_j * c]

                    // let b = sample.value * c - a * sample.point.y;
                    // copy sample value, 2 denote the incremental a, c
                    qm31_dup
                    { qm31_roll((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + j * 3 + 3) }
                    qm31_mul
                    if j == num_columns - 1 {
                        { qm31_roll((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + j * 3 + 3) }
                    } else {
                        { qm31_copy((num_points - 1 - i) * (num_columns + 1) + (num_columns - 1 - j) + j * 3 + 3) }
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

    /// Precompute the complex conjugate line coefficients for each column in each sample batch
    ///
    /// input:
    /// p: (QM31, QM31)
    /// F(p): QM31
    /// alpha: QM31
    ///
    /// output:
    /// [(`alpha^0 * a`, `alpha^0 * b`, `alpha^0 * c`), (`alpha^1 * a`, `alpha^1 * b`, `alpha^1 * c`), ...]
    pub fn column_line_coeffs(
        sample_batches: &[ColumnSampleBatch],
        random_coeff: SecureField,
    ) -> Script {
        script! {
            for sample_batch in sample_batches.iter() {
                // alpha
                { push_qm31_one() }
                for (_, sampled_value) in sample_batch.columns_and_values.iter() {
                    // update alpha, alpha^{i - 1} *= random_coeff
                    { random_coeff }
                    qm31_mul
                    // [alpha^i]

                    // let a = sample.value.complex_conjugate() - sample.value;
                    { *sampled_value }
                    qm31_dup
                    qm31_complex_conjugate
                    qm31_swap
                    qm31_sub
                    // [alpha^i, a]
                    qm31_over
                    qm31_mul
                    // [alpha^i, alpha^i * a]

                    // let c = sample.point.complex_conjugate().y - sample.point.y;
                    { sample_batch.point.y.1.1 }
                    m31_double
                    m31_neg
                    { sample_batch.point.y.1.0 }
                    m31_double
                    m31_neg
                    push_m31_zero
                    push_m31_zero
                    // [alpha^i, alpha^i * a, c]
                    { qm31_copy(2) }
                    qm31_mul
                    // [alpha^i, alpha^i * a, alpha^i * c]

                    // let b = sample.value * c - a * sample.point.y;
                    qm31_dup
                    { *sampled_value }
                    qm31_mul
                    { qm31_copy(2) }
                    { sample_batch.point.y }
                    qm31_mul
                    qm31_sub
                    // [alpha^i, alpha^i * a, alpha^i * c, alpha^i * b]

                    qm31_swap
                    { qm31_roll(3) }
                    // [alpha^i * a, alpha^i * b, alpha^i * c, alpha^i]
                }
                qm31_drop
                // [(alpha^n * a, alpha^n * c, alpha^i * b)]
            }
        }
    }

    //TODO: point_vanishing_fraction(). Depends on what format we'll end up needing its output in FRI

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
    /// input:
    ///  z.x (QM31)
    ///  z.y (QM31)
    ///
    /// output:
    ///  P(z)
    pub fn pair_vanishing(excluded0: CirclePoint<QM31>, excluded1: CirclePoint<QM31>) -> Script {
        script! {
            { excluded1.x - excluded0.x }
            qm31_mul    //(excluded1.x - excluded0.x) * z.y

            qm31_swap
            { excluded0.y - excluded1.y }
            qm31_mul    //(excluded0.y - excluded1.y) * z.x

            qm31_add
            { excluded0.x * excluded1.y - excluded0.y * excluded1.x }
            qm31_add
            //(excluded0.y - excluded1.y) * z.x
            //    + (excluded1.x - excluded0.x) * z.y
            //    + (excluded0.x * excluded1.y - excluded0.y * excluded1.x)
        }
    }
}

#[cfg(test)]
mod test {

    use crate::utils::get_rand_qm31;
    use crate::{
        constraints::ConstraintsGadget, tests_utils::report::report_bitcoin_script_size, treepp::*,
    };
    use itertools::Itertools;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::{qm31_equalverify, qm31_roll, qm31_rot};
    use stwo_prover::core::backend::cpu::quotients::column_line_coeffs;
    use stwo_prover::core::backend::cpu::CpuCirclePoly;
    use stwo_prover::core::circle::SECURE_FIELD_CIRCLE_GEN;
    use stwo_prover::core::circle::{CirclePoint, Coset};
    use stwo_prover::core::constraints::{coset_vanishing, pair_vanishing};
    use stwo_prover::core::fields::m31::M31;
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
    fn test_pair_vanishing() {
        for seed in 0..20 {
            let mut prng = ChaCha20Rng::seed_from_u64(seed);

            let z = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };

            let excluded0 = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };

            let excluded1 = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };

            let res = pair_vanishing(excluded0, excluded1, z);

            let pair_vanishing_script = ConstraintsGadget::pair_vanishing(excluded0, excluded1);
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
    fn test_column_line_coeffs_single() {
        const LOG_SIZE: u32 = 7;
        let polynomial = CpuCirclePoly::new((0..1 << LOG_SIZE).map(M31).collect());
        let sample_point = SECURE_FIELD_CIRCLE_GEN;
        let value = polynomial.eval_at_point(sample_point);

        let samples = vec![super::ColumnSampleBatch {
            point: sample_point,
            columns_and_values: vec![(0_usize, value)],
        }];
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let random_coeff = get_rand_qm31(&mut prng);
        let hints = column_line_coeffs(&samples, random_coeff);
        let num_points = hints.len();
        let num_columns = hints[0].len();
        println!("points {}, columns {}", num_points, num_columns);
        let script = script! {
            { ConstraintsGadget::column_line_coeffs(&samples, random_coeff) }
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
    fn test_column_line_coeffs_multiple() {
        let num_points = 4;
        let num_columns = 6;
        let generator = SECURE_FIELD_CIRCLE_GEN;

        let samples = (0..num_points)
            .map(|_| {
                let mut prng = ChaCha20Rng::seed_from_u64(6u64);
                let scalar: u32 = prng.gen();
                let sample_point = generator.mul(scalar as u128);
                let column_values = (0..num_columns)
                    .map(|i| (i, get_rand_qm31(&mut prng)))
                    .collect_vec();
                super::ColumnSampleBatch {
                    point: sample_point,
                    columns_and_values: column_values,
                }
            })
            .collect_vec();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let random_coeff = get_rand_qm31(&mut prng);
        let hints = column_line_coeffs(&samples, random_coeff);
        println!("points {}, columns {}", num_points, num_columns);
        let script = script! {
            { ConstraintsGadget::column_line_coeffs(&samples, random_coeff) }
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
    fn test_column_line_coeffs_new() {
        let num_points = 1_usize;
        let num_columns = 1_usize;
        let generator = SECURE_FIELD_CIRCLE_GEN;

        let samples = (0..num_points)
            .map(|_| {
                let mut prng = ChaCha20Rng::seed_from_u64(6u64);
                let scalar: u32 = prng.gen();
                let sample_point = generator.mul(scalar as u128);
                let column_values = (0..num_columns)
                    .map(|i| (i, get_rand_qm31(&mut prng)))
                    .collect_vec();
                super::ColumnSampleBatch {
                    point: sample_point,
                    columns_and_values: column_values,
                }
            })
            .collect_vec();

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let random_coeff = get_rand_qm31(&mut prng);
        let hints = column_line_coeffs(&samples, random_coeff);
        let alphas = (0..num_columns)
            .map(|i| random_coeff.pow(i as u128 + 1))
            .collect_vec();
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
            { ConstraintsGadget::column_line_coeffs_new(num_points, num_columns) }
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
}
