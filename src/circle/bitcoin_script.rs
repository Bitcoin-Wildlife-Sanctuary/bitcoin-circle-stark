use crate::treepp::*;
use rust_bitcoin_m31::{
    push_qm31_one, qm31_add, qm31_copy, qm31_double, qm31_equalverify, qm31_fromaltstack, qm31_mul,
    qm31_roll, qm31_square, qm31_sub, qm31_swap, qm31_toaltstack,
};

/// Gadget for points on the circle curve in the qm31 field.
pub struct CirclePointGadget;

impl CirclePointGadget {
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

    #[test]
    fn test_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let add_script = CirclePointGadget::add();
        report_bitcoin_script_size("CirclePoint", "add", add_script.len());

        let add_x_script = CirclePointGadget::add_x_only();
        report_bitcoin_script_size("CirclePoint", "add_x_only", add_x_script.len());

        for _ in 0..100 {
            let a = CirclePoint {
                x: QM31::from_m31(
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                ),
                y: QM31::from_m31(
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                ),
            };

            let b = CirclePoint {
                x: QM31::from_m31(
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                ),
                y: QM31::from_m31(
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                    M31::reduce(prng.next_u64()),
                ),
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
    fn test_double_x() {
        let double_x_script = CirclePointGadget::double_x();

        report_bitcoin_script_size("CirclePoint", "double_x", double_x_script.len());

        for seed in 0..20 {
            let mut prng = ChaCha20Rng::seed_from_u64(seed);

            let a = QM31::from_m31(
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
            );
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
