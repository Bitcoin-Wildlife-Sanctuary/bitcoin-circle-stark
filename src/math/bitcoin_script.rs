use bitvm::treepp::*;
use rust_bitcoin_m31::{
    qm31_add, qm31_copy, qm31_fromaltstack, qm31_mul_m31, qm31_sub, qm31_toaltstack,
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

            { qm31_copy(1) }
            { qm31_copy(1) }
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
    use crate::math::fft::ibutterfly;
    use crate::math::{FFTGadget, M31, QM31};
    use bitvm::treepp::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;

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
            qm31_equalverify
            { v0 }
            qm31_equalverify
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
