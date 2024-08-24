use crate::circle::CirclePointGadget;
use crate::treepp::*;
use rust_bitcoin_m31::{qm31_add, qm31_shift_by_i, qm31_shift_by_ij, qm31_shift_by_j, qm31_swap};
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
        assert!(!shifted.is_empty());

        script! {
            for elem in shifted.iter().take(shifted.len() - 1) {
                { CirclePointGadget::dup() }
                { CirclePointGadget::add_constant_m31_point(elem) }
                { CirclePointGadget::swap() }
            }
            { CirclePointGadget::add_constant_m31_point(shifted.last().unwrap()) }
        }
    }

    /// Mask a point by shifting it with signed mask
    ///
    /// Input:
    /// -  point (in qm31)
    ///
    /// Output:
    /// -  shifted point (in qm31)
    pub fn shifted_signed_mask_points(
        mask: &ColumnVec<Vec<isize>>,
        domains: &[CanonicCoset],
    ) -> Script {
        let mut shifted = vec![];
        for (mask_entry, domain) in mask.iter().zip(domains.iter()) {
            let step_point = domain.step();
            for mask_item in mask_entry.iter() {
                shifted.push(step_point.mul_signed(*mask_item));
            }
        }
        assert!(!shifted.is_empty());

        script! {
            for elem in shifted.iter().take(shifted.len() - 1) {
                { CirclePointGadget::dup() }
                { CirclePointGadget::add_constant_m31_point(elem) }
                { CirclePointGadget::swap() }
            }
            { CirclePointGadget::add_constant_m31_point(shifted.last().unwrap()) }
        }
    }

    /// Combine the evaluation on four points into one.
    ///
    /// Input:
    /// - a (qm31)
    /// - b (qm31)
    /// - c (qm31)
    /// - d (qm31)
    ///
    /// Output:
    /// - a * (1, 0, 0, 0) + b * (0, 1, 0, 0) + c * (0, 0, 1, 0) + d * (0, 0, 0, 1)
    pub fn eval_from_partial_evals() -> Script {
        script! {
            qm31_shift_by_ij
            qm31_swap
            qm31_shift_by_j
            qm31_add
            qm31_swap
            qm31_shift_by_i
            qm31_add
            qm31_add
        }
    }
}

#[cfg(test)]
mod test {
    use crate::air::{shifted_signed_mask_points, AirGadget};
    use crate::circle::CirclePointGadget;
    use crate::treepp::*;
    use crate::utils::get_rand_qm31;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::air::mask::shifted_mask_points;
    use stwo_prover::core::circle::{CirclePoint, SECURE_FIELD_CIRCLE_ORDER};
    use stwo_prover::core::fields::qm31::QM31;
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

    #[test]
    fn test_shifted_signed_mask_points() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let p = CirclePoint::get_point(prng.gen::<u128>() % SECURE_FIELD_CIRCLE_ORDER);

            let mask = vec![vec![0, -1, 2]];
            let domains = [CanonicCoset::new(5)];

            let expected = shifted_signed_mask_points(&mask, &domains, p);
            assert_eq!(expected.len(), 1);
            assert_eq!(expected[0].len(), 3);

            let script = script! {
                { p }
                { AirGadget::shifted_signed_mask_points(&mask, &domains) }
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

    #[test]
    fn test_eval_from_partial_evals() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a = get_rand_qm31(&mut prng);
            let b = get_rand_qm31(&mut prng);
            let c = get_rand_qm31(&mut prng);
            let d = get_rand_qm31(&mut prng);

            let mut res = a;
            res += b * QM31::from_u32_unchecked(0, 1, 0, 0);
            res += c * QM31::from_u32_unchecked(0, 0, 1, 0);
            res += d * QM31::from_u32_unchecked(0, 0, 0, 1);

            let script = script! {
                { a }
                { b }
                { c }
                { d }
                { AirGadget::eval_from_partial_evals() }
                { res }
                qm31_equalverify
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
