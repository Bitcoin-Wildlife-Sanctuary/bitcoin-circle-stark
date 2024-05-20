
use rust_bitcoin_u31_or_u30::{u31ext_double, u31ext_mul, u31ext_sub, QM31 as QM31Gadget};
use bitvm::treepp::*;

pub struct CirclePointSecureGadget;

impl CirclePointSecureGadget {

    // Rationale: cos(2*a) = 2*cos(a)^2-1
    //
    // input:
    //  x (QM31)
    //
    // output:
    //  2*x^2-1 (QM31)
    pub fn double_x() -> Script {
        script! {
            3 OP_PICK
            3 OP_PICK
            3 OP_PICK
            3 OP_PICK
            { u31ext_mul::<QM31Gadget>() }
            { u31ext_double::<QM31Gadget>() }
            { 0 as u32 }
            { 0 as u32 }
            { 0 as u32 }
            { 1 as u32 }
            { u31ext_sub::<QM31Gadget>() }
        }
    }

    // Samples a random point over the projective line, see Lemma 1 in https://eprint.iacr.org/2024/278.pdf
    //
    // input:
    //  channel
    //  !!need hints to squeeze QM31 from channel!!
    //  (1+t^2)^-1 - hint, where t is a QM31 squeezed from channel
    //
    // output:
    //  channel'=sha256(channel||0x00)
    //  (x,y) - random point on C(QM31) satisfying x^2+y^2=1
    pub fn get_random_point() -> Script {
        script! {
            OP_TRUE
        }
    }

    // input:
    //  NONE - this function does not update the channel, only peeks at its value
    // output:
    //  (1+t^2)^1 - hint, where t is a QM31 squeezed from channel
    pub fn push_1plustsquaredinv_hint(channel_digest: Vec<u8>) -> Script{
        script! {
            OP_TRUE
        }
    }
}

#[cfg(test)]
mod test {
    use bitvm::treepp::*;
    use p3_field::extension::Complex;
    use p3_field::{AbstractExtensionField, AbstractField, PrimeField32};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_u31_or_u30::{u31ext_equalverify, QM31 as QM31Gadget};

    type F = p3_field::extension::BinomialExtensionField<Complex<p3_mersenne_31::Mersenne31>, 2>;

    use crate::circle_secure::bitcoin_script::CirclePointSecureGadget;

    #[test]
    fn test_double_x(){
        for seed in 0..20 {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);

            let a = rng.gen::<F>();
            let double_a = a.square().double()-F::one();

            let a: &[Complex<p3_mersenne_31::Mersenne31>] = a.as_base_slice();
            let double_a: &[Complex<p3_mersenne_31::Mersenne31>] = double_a.as_base_slice();

            let script = script! {
                { a[1].imag().as_canonical_u32() }
                { a[1].real().as_canonical_u32() }
                { a[0].imag().as_canonical_u32() }
                { a[0].real().as_canonical_u32() }
                { CirclePointSecureGadget::double_x() }
                { double_a[1].imag().as_canonical_u32() }
                { double_a[1].real().as_canonical_u32() }
                { double_a[0].imag().as_canonical_u32() }
                { double_a[0].real().as_canonical_u32() }
                { u31ext_equalverify::<QM31Gadget>() }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}