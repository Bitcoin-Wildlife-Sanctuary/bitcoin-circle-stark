use crate::circle::CirclePoint;
use bitvm::treepp::*;
use rust_bitcoin_u31_or_u30::{u31_add, u31_mul, u31_neg, u31_sub, M31 as M31Gadget};

pub struct CirclePointGadget;

impl CirclePointGadget {
    pub fn zero() -> Script {
        script! {
            OP_PUSHNUM_1
            OP_PUSHBYTES_0
        }
    }

    pub fn push(point: &CirclePoint) -> Script {
        script! {
            { point.x.0 }
            { point.y.0 }
        }
    }

    pub fn add() -> Script {
        script! {
            3 OP_PICK
            2 OP_PICK
            { u31_mul::<M31Gadget>() }
            3 OP_PICK
            2 OP_PICK
            { u31_mul::<M31Gadget>() }
            5 OP_ROLL
            5 OP_ROLL
            { u31_add::<M31Gadget>() }
            4 OP_ROLL
            4 OP_ROLL
            { u31_add::<M31Gadget>() }
            { u31_mul::<M31Gadget>() }
            OP_TOALTSTACK
            OP_2DUP
            { u31_add::<M31Gadget>() }
            OP_FROMALTSTACK
            OP_SWAP
            { u31_sub::<M31Gadget>() }
            OP_TOALTSTACK
            { u31_sub::<M31Gadget>() }
            OP_FROMALTSTACK
        }
    }

    pub fn double() -> Script {
        script! {
            OP_2DUP
            { Self::add() }
        }
    }

    pub fn repeated_double(n: usize) -> Script {
        script! {
            for _ in 0..n {
                { Self::double() }
            }
        }
    }

    pub fn conjugate() -> Script {
        u31_neg::<M31Gadget>()
    }

    pub fn sub() -> Script {
        script! {
            { Self::conjugate() }
            { Self::add() }
        }
    }

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
    use crate::circle::CirclePoint;
    use crate::circle::CirclePointGadget;
    use crate::math::M31;
    use bitvm::treepp::*;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::ops::{Add, Sub};

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
