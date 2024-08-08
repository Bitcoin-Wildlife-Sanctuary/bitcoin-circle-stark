use crate::constraints::ConstraintsGadget;
use crate::treepp::*;
use num_traits::One;
use rust_bitcoin_m31::{
    qm31_add, qm31_copy, qm31_dup, qm31_equalverify, qm31_from_bottom, qm31_fromaltstack, qm31_mul,
    qm31_mul_m31, qm31_over, qm31_rot, qm31_square, qm31_sub, qm31_swap, qm31_toaltstack,
};
use stwo_prover::core::circle::{CirclePoint, Coset};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;

/// Gadget for Fibonacci composition polynomial-related operations.
pub struct FibonacciCompositionGadget;

impl FibonacciCompositionGadget {
    /// Compute the step constraint f(z)^2 + f(G z)^2 - f(G^2 z).
    ///
    /// Hint:
    /// - num/denom
    ///
    /// Input:
    /// - f(z)
    /// - f(Gz)
    /// - f(G^2 z)
    /// - z.x
    /// - z.y
    ///
    /// Output:
    /// - num/denom
    ///
    #[allow(dead_code)]
    fn step_constraint_eval_quotient_by_mask(log_size: u32) -> Script {
        let constraint_zero_domain = Coset::subgroup(log_size);

        script! {
            qm31_over
            qm31_over

            // (fg)^2 + f^2 - fg2,
            // x, y, x, y

            qm31_toaltstack
            qm31_toaltstack
            qm31_toaltstack
            qm31_toaltstack

            qm31_swap
            qm31_square
            qm31_rot
            qm31_square
            qm31_add

            qm31_swap
            qm31_sub // f(z)^2 + f(G z)^2 - f(G^2 z)

            qm31_fromaltstack
            qm31_fromaltstack
            {
                ConstraintsGadget::pair_vanishing_with_constant_m31_points(
                    constraint_zero_domain
                        .at(constraint_zero_domain.size() - 2),
                    constraint_zero_domain
                        .at(constraint_zero_domain.size() - 1),
                )
            }
            qm31_mul // num

            qm31_fromaltstack
            qm31_fromaltstack
            { ConstraintsGadget::coset_vanishing(constraint_zero_domain) } // denom

            qm31_from_bottom // num/denom
            qm31_dup
            qm31_toaltstack

            qm31_mul // denom*(num/denom)

            qm31_equalverify
            qm31_fromaltstack // num/denom
        }
    }

    /// Compute the boundary constraint f(0) = 1, f(end) = claim
    ///
    /// Hint:
    /// - num/denom
    ///
    /// Input:
    /// - f(z)
    /// - z.x
    /// - z.y
    ///
    /// Output:
    /// - num/denom
    ///
    fn boundary_constraint_eval_quotient_by_mask(log_size: u32, claim: M31) -> Script {
        let constraint_zero_domain = Coset::subgroup(log_size);
        let p = constraint_zero_domain.at(constraint_zero_domain.size() - 1);
        script! {
            qm31_dup
            qm31_toaltstack
            qm31_swap
            qm31_toaltstack // stack: f(z), z.y; altstack: z.y, z.x

            { (claim - M31::one()) * p.y.inverse() }
            qm31_mul_m31

            { QM31::one() }
            qm31_add // linear = QM31::one() + z.y * (self.claim - M31::one()) * p.y.inverse();

            qm31_sub // num = f(z) - linear

            qm31_fromaltstack // bring back z.x from altstack
            qm31_fromaltstack // bring back z.y from altstack
            { ConstraintsGadget::pair_vanishing_with_constant_m31_points(p, CirclePoint::zero())} // denom

            qm31_from_bottom // pull num/denom from hint

            qm31_dup
            qm31_toaltstack // store num/denom in altstack

            qm31_mul // (num/denom)*denom

            qm31_equalverify // check that num == (num/denom)*denom

            qm31_fromaltstack // return num/denom
        }
    }

    /// Computes the composition polynomial of Fibonacci
    ///
    /// Hint:
    /// - boundary result
    /// - step result
    ///
    /// Input:
    /// - alpha
    /// - f(z) (QM31)
    /// - f(Gz)
    /// - f(G^2 z)
    /// - z.x
    /// - z.y
    ///
    /// Output:
    /// - alpha * step_constraint(f(z),f(Gz),f(G^2 z),z) + boundary_constraint(f(z),z,claim)
    ///
    pub(crate) fn eval_composition_polynomial_at_point(log_size: u32, claim: M31) -> Script {
        script! {
            { qm31_copy(4) }
            { qm31_copy(2) }
            { qm31_copy(2) }
            { Self::boundary_constraint_eval_quotient_by_mask(log_size,claim) }
            qm31_toaltstack

            { Self::step_constraint_eval_quotient_by_mask(log_size) }
            qm31_mul

            qm31_fromaltstack
            qm31_add
        }
    }
}

#[cfg(test)]
mod test {
    use crate::air::CompositionHint;
    use crate::fibonacci::bitcoin_script::composition::FibonacciCompositionGadget;
    use crate::tests_utils::report::report_bitcoin_script_size;
    use crate::treepp::*;
    use crate::utils::get_rand_qm31;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use std::iter::zip;
    use stwo_prover::core::air::accumulation::PointEvaluationAccumulator;
    use stwo_prover::core::air::{AirProver, Component, ComponentProvers};
    use stwo_prover::core::fields::m31::M31;
    use stwo_prover::core::pcs::TreeVec;
    use stwo_prover::core::{InteractionElements, LookupValues};
    use stwo_prover::trace_generation::AirTraceGenerator;
    use stwo_prover::{
        core::{air::ComponentTrace, circle::CirclePoint, poly::circle::CanonicCoset},
        examples::fibonacci::Fibonacci,
    };

    #[test]
    fn test_eval_composition_polynomial_at_point() {
        let log_size = 5;
        let claim = M31::from_u32_unchecked(443693538);

        let fib = Fibonacci::new(log_size, claim);
        let trace = fib.get_trace();
        let trace_poly = trace.interpolate();
        let trace_eval =
            trace_poly.evaluate(CanonicCoset::new(trace_poly.log_size() + 1).circle_domain());
        let trace = ComponentTrace::new(
            TreeVec::new(vec![vec![&trace_poly]]),
            TreeVec::new(vec![vec![&trace_eval]]),
        );

        let component_traces = vec![trace];

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let composition_polynomial_script =
            FibonacciCompositionGadget::eval_composition_polynomial_at_point(log_size, claim);
        report_bitcoin_script_size(
            "Fibonacci",
            format!(
                "eval_composition_polynomial_at_point(log_size={})",
                log_size
            )
            .as_str(),
            composition_polynomial_script.len(),
        );

        for _ in 0..20 {
            let random_coeff = get_rand_qm31(&mut prng);

            let z = CirclePoint {
                x: get_rand_qm31(&mut prng),
                y: get_rand_qm31(&mut prng),
            };

            let air_prover = fib.air.to_air_prover();
            let components = ComponentProvers(air_prover.component_provers());

            let points = components.components().mask_points(z);
            let mask_values = zip(&component_traces[0].polys[0], &points[0])
                .map(|(poly, points)| {
                    points
                        .iter()
                        .map(|point| poly.eval_at_point(*point))
                        .collect_vec()
                })
                .collect_vec();

            let mut evaluation_accumulator = PointEvaluationAccumulator::new(random_coeff);
            fib.air.component.evaluate_constraint_quotients_at_point(
                z,
                &TreeVec::new(vec![mask_values.clone()]),
                &mut evaluation_accumulator,
                &InteractionElements::default(),
                &LookupValues::default(),
            );

            let res = evaluation_accumulator.finalize();

            let composition_hint = CompositionHint {
                constraint_eval_quotients_by_mask: vec![
                    fib.air.component.boundary_constraint_eval_quotient_by_mask(
                        z,
                        mask_values[0][..1].try_into().unwrap(),
                    ),
                    fib.air.component.step_constraint_eval_quotient_by_mask(
                        z,
                        mask_values[0][..].try_into().unwrap(),
                    ),
                ],
            };

            let script = script! {
                { composition_hint } // hint
                { random_coeff }
                { mask_values[0][0] }
                { mask_values[0][1] }
                { mask_values[0][2] }
                { z.x }
                { z.y }
                { composition_polynomial_script.clone() }
                { res }
                qm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
