

use rust_bitcoin_u31_or_u30::{u31ext_double, u31ext_mul, u31ext_sub, QM31 as QM31Gadget};
use bitvm::treepp::*;

use crate::{channel_extract::Extractor, math::{Field, QM31}};

pub struct CirclePointSecureGadget;

impl CirclePointSecureGadget {

    // Rationale: cos(2*theta) = 2*cos(theta)^2-1
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
    pub fn push_oneplustsquaredinv_hint(channel_digest: Vec<u8>) -> Script{
        //let mut hash: [u8; 32] = channel_digest.as_slice().try_into().clone();
        //let (t, _) = Extractor::extract_qm31(&hash);

        //let oneplustsquaredinv = t.square().add(QM31::one()).inverse();
        

        script! {
            OP_TRUE
        }
    }
}

#[cfg(test)]
mod test {
    use std::ops::{Add, Neg};

    use bitvm::treepp::*;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_u31_or_u30::{u31ext_equalverify, QM31 as QM31Gadget};

    use crate::{circle_secure::bitcoin_script::CirclePointSecureGadget, math::{Field, M31, QM31}};

    #[test]
    fn test_double_x(){
        for seed in 0..20 {
            let mut prng = ChaCha20Rng::seed_from_u64(seed);

            let a = QM31::from_m31(
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
                M31::reduce(prng.next_u64()),
            );
            let double_a = a.square().double().add(QM31::one().neg());

            let script = script! {
                { a }
                { CirclePointSecureGadget::double_x() }
                { double_a }
                { u31ext_equalverify::<QM31Gadget>() }
                OP_PUSHNUM_1
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}