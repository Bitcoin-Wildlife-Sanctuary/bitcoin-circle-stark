use crate::treepp::*;
use rust_bitcoin_m31::{
    qm31_add, qm31_fromaltstack, qm31_mul_m31, qm31_over, qm31_sub, qm31_toaltstack,
};

/// Gadget for FFT.
pub struct FFTGadget;

impl FFTGadget {
    /// Perform inverse butterfly in Bitcoin script.
    /// input:
    ///  v0 (qm31)
    ///  v1 (qm31)
    ///  itwid (m31)
    ///
    /// output:
    ///  v0' (qm31)
    ///  v1' (qm31)
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
    use crate::fri::FFTGadget;
    use crate::treepp::*;
    use crate::utils::get_rand_qm31;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::fft::ibutterfly;
    use stwo_prover::core::fields::m31::M31;

    #[test]
    fn test_ibutterfly() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

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
