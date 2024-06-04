use crate::treepp::*;
use rust_bitcoin_m31::{
    push_qm31_one, qm31_add, qm31_copy, qm31_double, qm31_equalverify, qm31_fromaltstack, qm31_mul,
    qm31_mul_by_constant, qm31_mul_m31_by_constant, qm31_roll, qm31_square, qm31_sub, qm31_swap,
    qm31_toaltstack,
};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

/// Gadget for points on the circle curve in the qm31 field.
pub struct CirclePointGadget;

impl CirclePointGadget {
    /// Duplicate the circle point
    pub fn dup() -> Script {
        script! {
            { qm31_copy(1) }
            { qm31_copy(1) }
        }
    }

    /// Swap two circle points on the stack
    pub fn swap() -> Script {
        script! {
            { qm31_roll(3) }
            { qm31_roll(3) }
        }
    }

    /// Drop a circle point
    pub fn drop() -> Script {
        script! {
            OP_2DROP OP_2DROP
            OP_2DROP OP_2DROP
        }
    }

    /// Only computes the x component of addition between points
    pub fn add_x_only() -> Script {
        script! {
            { qm31_roll(3) }
            { qm31_roll(2) }
            qm31_mul
            { qm31_roll(1) }
            { qm31_roll(2) }
            qm31_mul
            qm31_sub
        }
    }

    /// Add two points.
    ///
    /// Input:
    /// - p.x (qm31)
    /// - p.y
    /// - q.x
    /// - q.y
    ///
    /// Output:
    /// - sum.x
    /// - sum.y
    ///
    pub fn add() -> Script {
        script! {
            { qm31_copy(3) }
            { qm31_copy(2) }
            qm31_mul
            { qm31_copy(3) }
            { qm31_copy(2) }
            qm31_mul
            { qm31_roll(5)}
            { qm31_roll(5)}
            qm31_add
            { qm31_roll(4)}
            { qm31_roll(4)}
            qm31_add
            qm31_mul
            qm31_toaltstack
            { qm31_copy(1) }
            { qm31_copy(1) }
            qm31_add
            qm31_fromaltstack
            qm31_swap
            qm31_sub
            qm31_toaltstack
            qm31_sub
            qm31_fromaltstack
        }
    }

    /// Add a constant point.
    ///
    /// Input:
    /// - p.x (qm31)
    /// - p.y
    ///
    /// Output:
    /// - sum.x
    /// - sum.y
    ///
    pub fn add_constant_point(point: &CirclePoint<QM31>) -> Script {
        script! {
            // compute p.y * q.y
            { qm31_copy(0) }
            { qm31_mul_by_constant(
                point.y.1.1.0,
                point.y.1.0.0,
                point.y.0.1.0,
                point.y.0.0.0
            ) }
            qm31_toaltstack

            // compute p.x * q.x
            { qm31_copy(1) }
            { qm31_mul_by_constant(
                point.x.1.1.0,
                point.x.1.0.0,
                point.x.0.1.0,
                point.x.0.0.0
            ) }
            qm31_toaltstack

            // compute (p.x + p.y) * (q.x + q.y)
            qm31_add
            { qm31_mul_by_constant(
                (point.x.1.1 + point.y.1.1).0,
                (point.x.1.0 + point.y.1.0).0,
                (point.x.0.1 + point.y.0.1).0,
                (point.x.0.0 + point.y.0.0).0
            ) }

            // stack: (p.x + p.y) * (q.x + q.y)
            // altstack: p.y * q.y, p.x * q.x

            qm31_fromaltstack
            qm31_swap
            { qm31_copy(1) }
            qm31_sub

            qm31_fromaltstack
            qm31_swap
            { qm31_copy(1) }
            qm31_sub

            // stack: p.x * q.x, p.y * q.y, p.x * q.y + p.y * q.x

            qm31_toaltstack
            qm31_sub
            qm31_fromaltstack
        }
    }

    /// Add a constant point.
    ///
    /// Input:
    /// - p.x (qm31)
    /// - p.y
    ///
    /// Output:
    /// - sum.x
    /// - sum.y
    ///
    pub fn add_constant_m31_point(point: &CirclePoint<M31>) -> Script {
        script! {
            // compute p.y * q.y
            { qm31_copy(0) }
            { qm31_mul_m31_by_constant(point.y.0) }
            qm31_toaltstack

            // compute p.x * q.x
            { qm31_copy(1) }
            { qm31_mul_m31_by_constant(point.x.0) }
            qm31_toaltstack

            // compute (p.x + p.y) * (q.x + q.y)
            qm31_add
            { qm31_mul_m31_by_constant((point.x + point.y).0) }

            // stack: (p.x + p.y) * (q.x + q.y)
            // altstack: p.y * q.y, p.x * q.x

            qm31_fromaltstack
            qm31_swap
            { qm31_copy(1) }
            qm31_sub

            qm31_fromaltstack
            qm31_swap
            { qm31_copy(1) }
            qm31_sub

            // stack: p.x * q.x, p.y * q.y, p.x * q.y + p.y * q.x

            qm31_toaltstack
            qm31_sub
            qm31_fromaltstack
        }
    }

    /// Fail the execution if the two points are not equal.
    pub fn equalverify() -> Script {
        script! {
            { qm31_roll(2) }
            qm31_equalverify
            qm31_equalverify
        }
    }

    /// Double a point.
    /// Rationale: cos(2*theta) = 2*cos(theta)^2-1
    ///
    /// input:
    ///  x (QM31)
    ///
    /// output:
    ///  2*x^2-1 (QM31)
    pub fn double_x() -> Script {
        script! {
            qm31_square
            qm31_double
            push_qm31_one
            qm31_sub
        }
    }
}

#[cfg(test)]
mod test {
    use num_traits::One;
    use std::ops::{Add, Neg};
    use stwo_prover::core::circle::CirclePoint;

    use crate::{tests_utils::report::report_bitcoin_script_size, treepp::*};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::fields::m31::M31;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fields::{Field, FieldExpOps};

    use crate::circle::CirclePointGadget;
    use crate::utils::get_rand_qm31;

    #[test]
    fn test_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let add_script = CirclePointGadget::add();
        report_bitcoin_script_size("CirclePoint", "add", add_script.len());

        let add_x_script = CirclePointGadget::add_x_only();
        report_bitcoin_script_size("CirclePoint", "add_x_only", add_x_script.len());

        for _ in 0..100 {
            let a = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };

            let b = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };
            let c = a + b;

            let script = script! {
                { a.x }
                { a.y }
                { b.x }
                { b.y }
                { add_script.clone() }
                { c.x }
                { c.y }
                { CirclePointGadget::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            let script = script! {
                { a.x }
                { a.y }
                { b.x }
                { b.y }
                { add_x_script.clone() }
                { c.x }
                qm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_add_constant_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut total_len = 0;

        for _ in 0..100 {
            let a = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };

            let b = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };
            let c = a + b;

            let add_script = CirclePointGadget::add_constant_point(&b);
            total_len += add_script.len();

            let script = script! {
                { a.x }
                { a.y }
                { add_script.clone() }
                { c.x }
                { c.y }
                { CirclePointGadget::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
        report_bitcoin_script_size("CirclePoint", "add_constant_point", total_len / 100);
    }

    #[test]
    fn test_add_constant_m31_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut total_len = 0;

        for _ in 0..100 {
            let a = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };

            let b = CirclePoint {
                x: M31::reduce(prng.next_u64()),
                y: M31::reduce(prng.next_u64()),
            };
            let c = a + b.into_ef();

            let add_script = CirclePointGadget::add_constant_m31_point(&b);
            total_len += add_script.len();

            let script = script! {
                { a.x }
                { a.y }
                { add_script.clone() }
                { c.x }
                { c.y }
                { CirclePointGadget::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
        report_bitcoin_script_size("CirclePoint", "add_constant_m31_point", total_len / 100);
    }

    #[test]
    fn test_double_x() {
        let double_x_script = CirclePointGadget::double_x();

        report_bitcoin_script_size("CirclePoint", "double_x", double_x_script.len());

        for seed in 0..20 {
            let mut prng = ChaCha20Rng::seed_from_u64(seed);

            let a = get_rand_qm31(&mut prng);
            let double_a = a.square().double().add(QM31::one().neg());

            let script = script! {
                { a }
                { double_x_script.clone() }
                { double_a }
                qm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
