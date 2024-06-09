use crate::{circle::CirclePointGadget, treepp::*};
use rust_bitcoin_m31::{m31_add, qm31_add, qm31_mul_m31_by_constant, qm31_swap};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::{
    circle::{CirclePoint, Coset},
    fields::qm31::QM31,
};

/// Gadget for constraints over the circle curve
pub struct ConstraintsGadget;

impl ConstraintsGadget {
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
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::circle::{
        CirclePoint, Coset, M31_CIRCLE_GEN, SECURE_FIELD_CIRCLE_ORDER,
    };
    use stwo_prover::core::constraints::{coset_vanishing, pair_vanishing};

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
}
