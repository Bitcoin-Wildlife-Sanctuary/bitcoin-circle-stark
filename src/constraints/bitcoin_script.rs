use crate::treepp::*;
use rust_bitcoin_m31::{qm31_add, qm31_mul, qm31_swap};
use std::ops::{Add, Mul, Neg};

use crate::math::QM31;

/// Gadget for constraints over the circle curve
pub struct ConstraintsGadget;

impl ConstraintsGadget {
    /// Evaluates a polynomial P : CirclePointSecure -> QM31 that vanishes at excluded0 and excluded1
    ///
    /// input:
    ///  z.x (QM31)
    ///  z.y (QM31)
    ///
    /// output:
    ///  P(z)
    pub fn pair_vanishing(
        excluded0x: QM31,
        excluded0y: QM31,
        excluded1x: QM31,
        excluded1y: QM31,
    ) -> Script {
        script! {
            { excluded1x.add(excluded0x.neg()) }
            qm31_mul    //(excluded1.x - excluded0.x) * z.y

            qm31_swap
            { excluded0y.add(excluded1y.neg()) }
            qm31_mul    //(excluded0.y - excluded1.y) * z.x

            qm31_add
            { excluded0x.mul(excluded1y).add(excluded0y.mul(excluded1x).neg())}
            qm31_add
            //(excluded0.y - excluded1.y) * z.x
            //    + (excluded1.x - excluded0.x) * z.y
            //    + (excluded0.x * excluded1.y - excluded0.y * excluded1.x)
        }
    }
}

#[cfg(test)]
mod test {
    use std::ops::{Add, Mul, Neg};

    use crate::{constraints::ConstraintsGadget, treepp::*};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;

    use crate::math::{M31, QM31};

    #[test]
    fn test_pair_vanishing() {
        for seed in 0..20 {
            let mut prng = ChaCha20Rng::seed_from_u64(seed);

            let zx = QM31::from_m31(
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
            );

            let zy = QM31::from_m31(
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
            );

            let e0x = QM31::from_m31(
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
            );

            let e0y = QM31::from_m31(
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
            );

            let e1x = QM31::from_m31(
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
            );

            let e1y = QM31::from_m31(
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
            );

            //(excluded0.y - excluded1.y) * z.x
            //    + (excluded1.x - excluded0.x) * z.y
            //    + (excluded0.x * excluded1.y - excluded0.y * excluded1.x)
            let res = e0y
                .add(e1y.neg())
                .mul(zx)
                .add(e1x.add(e0x.neg()).mul(zy))
                .add(e0x.mul(e1y).add(e0y.mul(e1x).neg()));

            let script = script! {
                { zx }
                { zy }
                { ConstraintsGadget::pair_vanishing(e0x,e0y,e1x,e1y) }
                { res }
                qm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
