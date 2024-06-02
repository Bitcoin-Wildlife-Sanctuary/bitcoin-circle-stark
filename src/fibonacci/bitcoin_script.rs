use core::slice;

use crate::{constraints::ConstraintsGadget, fibonacci::FibonacciComposition, treepp::*};
use num_traits::One;
use rust_bitcoin_m31::qm31_add;
use rust_bitcoin_m31::qm31_dup;
use rust_bitcoin_m31::qm31_equalverify;
use rust_bitcoin_m31::qm31_from_bottom;
use rust_bitcoin_m31::{
    qm31_fromaltstack, qm31_mul, qm31_mul_m31, qm31_roll, qm31_sub, qm31_toaltstack,
};
use stwo_prover::core::{
    circle::{CirclePoint, Coset},
    fields::{m31::M31, qm31::QM31, FieldExpOps},
};

/// Gadget for Fibonacci composition polynomial-related operations.
pub struct FibonacciCompositionGadget;

impl FibonacciCompositionGadget {
    /*fn step_constraint_eval_quotient_by_mask() -> Script {
        script! {

        }
    }*/

    ///hint
    #[allow(dead_code)]
    fn boundary_constraint_eval_quotient_by_mask_hint(
        log_size: u32,
        claim: M31,
        z: CirclePoint<QM31>,
        fz: QM31,
    ) -> Script {
        let res = FibonacciComposition::boundary_constraint_eval_quotient_by_mask(
            log_size,
            claim,
            z,
            slice::from_ref(&fz).try_into().unwrap(),
        );

        script! {
            { res }
        }
    }

    //give result as hint, compute num,denom yourself and verify
    ///hint:
    /// num/denom
    ///input:
    /// f(z)
    /// z.x
    /// z.y
    ///output:
    /// num/denom
    #[allow(dead_code)]
    fn boundary_constraint_eval_quotient_by_mask(log_size: u32, claim: M31) -> Script {
        let constraint_zero_domain = Coset::subgroup(log_size);
        let p = constraint_zero_domain.at(constraint_zero_domain.size() - 1);
        script! {
            qm31_dup
            qm31_toaltstack
            { qm31_roll(1) }
            qm31_toaltstack //stack: f(z), z.y; altstack: z.y, z.x

            { (claim - M31::one()) * p.y.inverse() }
            qm31_mul_m31

            { QM31::one() }
            qm31_add //linear = QM31::one() + z.y * (self.claim - M31::one()) * p.y.inverse();

            qm31_sub //num = f(z) - linear
            //OP_RETURN

            qm31_fromaltstack //bring back z.x from altstack
            qm31_fromaltstack //bring back z.y from altstack
            { ConstraintsGadget::pair_vanishing(p.into_ef(), CirclePoint::zero())} //denom

            qm31_from_bottom //pull num/denom from hint

            qm31_dup
            qm31_toaltstack //store num/denom in altstack

            qm31_mul //(num/denom)*denom

            qm31_equalverify //check that num==(num/denom)*denom

            qm31_fromaltstack //return num/denom
        }
    }

    //step_constraint_eval_quotient_by_mask(f(z'),f(G z'),f(G^2 z'),z)*alpha + boundary_constraint_eval_quotient_by_mask(f(z'),z)
    //eval_composition_polynomial_at_point()->evaluate_constraint_quotients_at_point()->
    //no accumulator
    //alpha should be taken from channel

    /*
    ///input:
    /// alpha
    /// f(G^2 z)
    /// f(Gz)
    /// f(z) (QM31)
    /// z.x
    /// z.y
    fn eval_composition_polynomial_at_point(log_size: u32, claim: M31) -> Script {
        script! {

        }
    }*/
}

#[cfg(test)]
mod test {
    use core::slice;

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::{
        circle::CirclePoint,
        fields::{
            m31::{self, M31},
            qm31::QM31,
        },
    };

    use crate::fibonacci::{FibonacciComposition, FibonacciCompositionGadget};
    use crate::treepp::*;

    #[test]
    fn test_boundary_constraint_eval_quotient_by_mask() {
        let log_size = 5;
        let claim = m31::M31::from_u32_unchecked(443693538);

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let z = CirclePoint {
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

        let fz = QM31::from_m31(
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
        );

        let res = FibonacciComposition::boundary_constraint_eval_quotient_by_mask(
            log_size,
            claim,
            z,
            slice::from_ref(&fz).try_into().unwrap(),
        );

        let script = script! {
            { FibonacciCompositionGadget::boundary_constraint_eval_quotient_by_mask_hint(log_size, claim, z, fz) } //hint
            { fz }
            { z.x }
            { z.y }
            { FibonacciCompositionGadget::boundary_constraint_eval_quotient_by_mask(log_size,claim) }
            { res }
            qm31_equalverify
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
