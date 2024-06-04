use crate::circle::CirclePointGadget;
use crate::treepp::*;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::ColumnVec;

type Mask = ColumnVec<Vec<usize>>;

/// Gadget for operations that are specific to AIR.
pub struct AirGadget;

impl AirGadget {
    /// Mask a point by shifting it (note: shifting with an M31 point).
    ///
    /// Input:
    /// -  point (in qm31)
    ///
    /// Output:
    /// -  shifted point (in qm31)
    pub fn shifted_mask_points(mask: &Mask, domains: &[CanonicCoset]) -> Script {
        let mut shifted = vec![];
        for (mask_entry, domain) in mask.iter().zip(domains.iter()) {
            for mask_item in mask_entry.iter() {
                shifted.push(domain.at(*mask_item));
            }
        }

        script! {
            if !shifted.is_empty() {
                for elem in shifted.iter().take(shifted.len() - 1) {
                    { CirclePointGadget::dup() }
                    { CirclePointGadget::add_constant_m31_point(elem) }
                    { CirclePointGadget::swap() }
                }
                { CirclePointGadget::add_constant_m31_point(shifted.last().unwrap()) }
            } else {
                { CirclePointGadget::drop() }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::air::AirGadget;
    use crate::circle::CirclePointGadget;
    use crate::treepp::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_prover::core::air::mask::shifted_mask_points;
    use stwo_prover::core::circle::{CirclePoint, SECURE_FIELD_CIRCLE_ORDER};
    use stwo_prover::core::poly::circle::CanonicCoset;

    #[test]
    fn test_shifted_mask_points() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let p = CirclePoint::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);

            let mask = vec![vec![0, 1, 2]];
            let domains = [CanonicCoset::new(5)];

            let expected = shifted_mask_points(&mask, &domains, p);
            assert_eq!(expected.len(), 1);
            assert_eq!(expected[0].len(), 3);

            let script = script! {
                { p }
                { AirGadget::shifted_mask_points(&mask, &domains) }
                { expected[0][2] }
                { CirclePointGadget::equalverify() }
                { expected[0][1] }
                { CirclePointGadget::equalverify() }
                { expected[0][0] }
                { CirclePointGadget::equalverify() }
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
