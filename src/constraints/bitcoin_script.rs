use crate::{circle::CirclePointGadget, treepp::*};
use rust_bitcoin_m31::{qm31_add, qm31_mul, qm31_swap};
use stwo_prover::core::{
    circle::{CirclePoint, Coset},
    fields::qm31::QM31,
};

/// Gadget for constraints over the circle curve
pub struct ConstraintsGadget;

impl ConstraintsGadget {
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

    /// Evaluates a polynomial P : CirclePointSecure -> QM31 that vanishes at excluded0 and excluded1
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

    use crate::{constraints::ConstraintsGadget, treepp::*};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::circle::{CirclePoint, Coset};
    use stwo_prover::core::constraints::{coset_vanishing, pair_vanishing};
    use stwo_prover::core::fields::m31::M31;
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

            let excluded0 = CirclePoint {
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

            let excluded1 = CirclePoint {
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

            let res = pair_vanishing(excluded0, excluded1, z);

            let pair_vanishing_script = ConstraintsGadget::pair_vanishing(excluded0, excluded1);
            if seed == 0 {
                println!(
                    "Constraints.pair_vanishing() = {} bytes",
                    pair_vanishing_script.len()
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
