use bitvm::treepp::*;
use rust_bitcoin_u31_or_u30::QM31 as QM31Gadget;
use rust_bitcoin_u31_or_u30::{
    u31ext_add, u31ext_copy, u31ext_fromaltstack, u31ext_mul_u31, u31ext_sub, u31ext_toaltstack,
};

pub struct FFTGadget;

impl FFTGadget {
    pub fn ibutterfly() -> Script {
        // input:
        //  v0 (qm31)
        //  v1 (qm31)
        //  itwid (m31)
        //
        // output:
        //  v0' (qm31)
        //  v1' (qm31)

        script! {
            OP_TOALTSTACK

            { u31ext_copy::<QM31Gadget>(1) }
            { u31ext_copy::<QM31Gadget>(1) }
            { u31ext_sub::<QM31Gadget>() }

            OP_FROMALTSTACK
            { u31ext_mul_u31::<QM31Gadget>() }

            { u31ext_toaltstack::<QM31Gadget>() }

            { u31ext_add::<QM31Gadget>() }

            { u31ext_fromaltstack::<QM31Gadget>() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::math::fft::ibutterfly;
    use crate::math::{FFTGadget, M31, QM31};
    use bitvm::treepp::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_u31_or_u30::u31ext_equalverify;
    use rust_bitcoin_u31_or_u30::QM31 as QM31Gadget;

    #[test]
    fn test_ibutterfly() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a = QM31::from_m31(
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
        );

        let b = QM31::from_m31(
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
        );

        let itwid = M31::reduce(prng.next_u64());

        let mut v0 = a.clone();
        let mut v1 = b.clone();

        ibutterfly(&mut v0, &mut v1, itwid.into());

        let script = script! {
            { a }
            { b }
            { itwid }
            { FFTGadget::ibutterfly() }
            { v1 }
            { u31ext_equalverify::<QM31Gadget>() }
            { v0 }
            { u31ext_equalverify::<QM31Gadget>() }
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
