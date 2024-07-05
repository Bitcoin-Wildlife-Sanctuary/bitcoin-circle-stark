use crate::treepp::*;
use rust_bitcoin_m31::{
    m31_from_bottom, m31_mul, push_m31_one, qm31_add, qm31_fromaltstack, qm31_mul_m31, qm31_over,
    qm31_sub, qm31_toaltstack,
};

/// Gadget for inversion needed for the IFFT parameter.
pub struct FieldInversionGadget;

impl FieldInversionGadget {
    /// Inverse a field element using a hint.
    ///
    /// Input:
    /// - elem
    ///
    /// Output:
    /// - elem inv
    pub fn inverse_with_hint() -> Script {
        script! {
            // pull an element
            m31_from_bottom
            OP_SWAP OP_OVER m31_mul push_m31_one OP_EQUALVERIFY
        }
    }
}

/// Gadget for FFT.
pub struct FFTGadget;

impl FFTGadget {
    /// Perform inverse butterfly in Bitcoin script.
    ///
    /// Input:
    /// - v0 (qm31)
    /// - v1 (qm31)
    /// - itwid (m31)
    ///
    /// Output:
    /// - v0' (qm31)
    /// - v1' (qm31)
    pub fn ibutterfly() -> Script {
        script! {
            OP_TOALTSTACK

            qm31_over
            qm31_over
            qm31_sub

            OP_FROMALTSTACK
            qm31_mul_m31

            qm31_toaltstack

            qm31_add

            qm31_fromaltstack
        }
    }
}

#[cfg(test)]
mod test {
    use crate::fri::{FFTGadget, FieldInversionGadget, FieldInversionHint};
    use crate::treepp::*;
    use crate::utils::get_rand_qm31;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::fft::ibutterfly;
    use stwo_prover::core::fields::m31::M31;
    use stwo_prover::core::fields::FieldExpOps;

    #[test]
    fn test_inverse() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let elem_before_inverse = M31::reduce(prng.next_u64());

            let elem = elem_before_inverse.inverse();
            let h = FieldInversionHint::from(elem_before_inverse);

            let script = script! {
                { h }
                { elem_before_inverse }
                { FieldInversionGadget::inverse_with_hint() }
                { elem }
                OP_EQUAL
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_ibutterfly() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = get_rand_qm31(&mut prng);

            let b = get_rand_qm31(&mut prng);

            let itwid = M31::reduce(prng.next_u64());

            let mut v0 = a;
            let mut v1 = b;

            ibutterfly(&mut v0, &mut v1, itwid);

            let script = script! {
                { a }
                { b }
                { itwid }
                { FFTGadget::ibutterfly() }
                { v1 }
                qm31_equalverify
                { v0 }
                qm31_equalverify
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
