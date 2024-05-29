use crate::treepp::*;
use rust_bitcoin_m31::{m31_add, m31_mul, m31_neg, m31_sub};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::M31;

/// Gadget for points on the circle curve over the m31 field.
/// This is not the secure field.
pub struct CirclePointGadget;

impl CirclePointGadget {
    /// Push a zero point.
    pub fn zero() -> Script {
        script! {
            OP_PUSHNUM_1
            OP_PUSHBYTES_0
        }
    }

    /// Push a constant point.
    pub fn push(point: &CirclePoint<M31>) -> Script {
        script! {
            { point.x.0 }
            { point.y.0 }
        }
    }

    /// Add two points.
    pub fn add() -> Script {
        script! {
            3 OP_PICK
            2 OP_PICK
            m31_mul
            3 OP_PICK
            2 OP_PICK
            m31_mul
            5 OP_ROLL
            5 OP_ROLL
            m31_add
            4 OP_ROLL
            4 OP_ROLL
            m31_add
            m31_mul
            OP_TOALTSTACK
            OP_2DUP
            m31_add
            OP_FROMALTSTACK
            OP_SWAP
            m31_sub
            OP_TOALTSTACK
            m31_sub
            OP_FROMALTSTACK
        }
    }

    /// Double the point.
    pub fn double() -> Script {
        script! {
            OP_2DUP
            { Self::add() }
        }
    }

    /// Double the point repeatedly for n times.
    pub fn repeated_double(n: usize) -> Script {
        script! {
            for _ in 0..n {
                { Self::double() }
            }
        }
    }

    /// Negate a point.
    pub fn conjugate() -> Script {
        m31_neg()
    }

    /// Subtract two points.
    pub fn sub() -> Script {
        script! {
            { Self::conjugate() }
            { Self::add() }
        }
    }

    /// Fail the execution if the two points are not equal.
    pub fn equalverify() -> Script {
        script! {
            OP_ROT
            OP_EQUALVERIFY
            OP_EQUALVERIFY
        }
    }
}

#[cfg(test)]
mod test {
    use crate::circle::CirclePointGadget;
    use crate::treepp::*;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::ops::{Add, Sub};
    use stwo_prover::core::circle::CirclePoint;
    use stwo_prover::core::fields::m31::M31;

    #[test]
    fn test_double() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let double_script = CirclePointGadget::double();
        println!("CirclePoint.double() = {} bytes", double_script.len());

        for _ in 0..100 {
            let a = CirclePoint {
                x: M31::reduce(prng.next_u64()),
                y: M31::reduce(prng.next_u64()),
            };
            let b = a.double();

            let script = script! {
                { CirclePointGadget::push(&a) }
                { double_script.clone() }
                { CirclePointGadget::push(&b) }
                { CirclePointGadget::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let add_script = CirclePointGadget::add();
        println!("CirclePoint.add() = {} bytes", add_script.len());

        for _ in 0..100 {
            let a = CirclePoint {
                x: M31::reduce(prng.next_u64()),
                y: M31::reduce(prng.next_u64()),
            };
            let b = CirclePoint {
                x: M31::reduce(prng.next_u64()),
                y: M31::reduce(prng.next_u64()),
            };
            let c = a.add(b);

            let script = script! {
                { CirclePointGadget::push(&a) }
                { CirclePointGadget::push(&b) }
                { add_script.clone() }
                { CirclePointGadget::push(&c) }
                { CirclePointGadget::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_sub() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let sub_script = CirclePointGadget::sub();
        println!("CirclePoint.sub() = {} bytes", sub_script.len());

        for _ in 0..100 {
            let a = CirclePoint {
                x: M31::reduce(prng.next_u64()),
                y: M31::reduce(prng.next_u64()),
            };
            let b = CirclePoint {
                x: M31::reduce(prng.next_u64()),
                y: M31::reduce(prng.next_u64()),
            };
            let c = a.sub(b);

            let script = script! {
                { CirclePointGadget::push(&a) }
                { CirclePointGadget::push(&b) }
                { sub_script.clone() }
                { CirclePointGadget::push(&c) }
                { CirclePointGadget::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
