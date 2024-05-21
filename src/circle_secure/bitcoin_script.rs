use std::ops::{Add, Mul, Neg};

use rust_bitcoin_u31_or_u30::{u31ext_add, u31ext_copy, u31ext_double, u31ext_equalverify, u31ext_fromaltstack, u31ext_mul, u31ext_roll, u31ext_sub, u31ext_toaltstack, QM31 as QM31Gadget};
use bitvm::treepp::*;

use crate::{channel::ChannelGadget, channel_extract::Extractor, math::{Field, QM31}};

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
            { u31ext_copy::<QM31Gadget>(0) }
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
    //  y - hint such that 2*t = y*(1+t^2)
    //  x - hint such that 1-t^2 = x*(1+t^2)
    //      where t is extracted from channel
    //  qm31 hint (5 elements)
    //  channel
    //
    // output:
    //  y
    //  x
    //      where (x,y) - random point on C(QM31) satisfying x^2+y^2=1 (8 elements)
    //  channel'=sha256(channel)
    pub fn get_random_point() -> Script {
        script! {
            { ChannelGadget::squeeze_element_using_hint() } //stack: y,x,t,channel'
            /*OP_TOALTSTACK //stack: y,x,t; altstack: channel'
            { u31ext_copy::<QM31Gadget>(1) } //stack: y,x,t,x; altstack: channel'
            { u31ext_toaltstack::<QM31Gadget>() } //stack: y,x,t; altstack: channel',x
            { u31ext_copy::<QM31Gadget>(2) } //stack: y,x,t,y; altstack: channel',x
            { u31ext_toaltstack::<QM31Gadget>() }  //stack: y,x,t; altstack: channel',x,y
            { u31ext_copy::<QM31Gadget>(0) }  //stack: y,x,t,t; altstack: channel'
            { u31ext_double::<QM31Gadget>() } //stack: y,x,t,2*t; altstack: channel'
            { u31ext_toaltstack::<QM31Gadget>() }  //stack: y,x,t; altstack: channel',x,y,2*t
            { u31ext_copy::<QM31Gadget>(0) } //stack: y,x,t,t; altstack: channel',x,y,2*t
            { u31ext_mul::<QM31Gadget>() } //stack: y,x,t^2; altstack: channel',x,y,2*t
            { u31ext_copy::<QM31Gadget>(0) } //stack: y,x,t^2,t^2; altstack: channel',x,y,2*t
            { 0 as u32 }
            { 0 as u32 }
            { 0 as u32 }
            { 1 as u32 } //stack: y,x,t^2,t^2,1; altstack: channel',x,y,2*t
            { u31ext_roll::<QM31Gadget>(0) } //stack: y,x,t^2,1,t^2; altstack: channel',x,y,2*t
            { u31ext_sub::<QM31Gadget>() } //stack: y,x,t^2,1-t^2; altstack: channel',x,y,2*t
            { u31ext_toaltstack::<QM31Gadget>() } //stack: y,x,t^2; altstack: channel',x,y,2*t,1-t^2
            { 0 as u32 }
            { 0 as u32 }
            { 0 as u32 }
            { 1 as u32 }
            { u31ext_add::<QM31Gadget>() } //stack: y,x,1+t^2; altstack: channel',x,y,2*t,1-t^2
            { u31ext_copy::<QM31Gadget>(0) } //stack: y,x,1+t^2,1+t^2; altstack: channel',x,y,2*t,1-t^2
            { u31ext_roll::<QM31Gadget>(1) } //stack: y,1+t^2,1+t^2,x; altstack: channel',x,y,2*t,1-t^2
            { u31ext_mul::<QM31Gadget>() } //stack: y,1+t^2,(1+t^2)*x; altstack: channel',x,y,2*t,1-t^2
            { u31ext_toaltstack::<QM31Gadget>() } //stack: y,1+t^2,(1+t^2)*x,1-t^2; altstack: channel',x,y,2*t
            { u31ext_equalverify::<QM31Gadget>() } //stack: y,1+t^2; altstack: channel',x,y,2*t
            { u31ext_mul::<QM31Gadget>() } //stack: y*(1+t^2); altstack: channel',x,y,2*t,1-t^2
            { u31ext_toaltstack::<QM31Gadget>() } //stack: y*(1+t^2),1-t^2; altstack: channel',x,y,2*t
            { u31ext_equalverify::<QM31Gadget>() } //stack: ; altstack: channel',x,y
            OP_FROMALTSTACK { u31ext_fromaltstack::<QM31Gadget>() } { u31ext_fromaltstack::<QM31Gadget>() } //stack: y,x,channel'
            
            */
        }
    }

    // input:
    //  NONE - this function does not update the channel, only peeks at its value
    //
    // output:
    //  y
    //  x
    pub fn push_random_point_hint(channel_digest: Vec<u8>) -> Script{
        let hash: [u8; 32] = channel_digest.as_slice().try_into().unwrap();
        let (t, _) = Extractor::extract_qm31(&hash);

        let oneplustsquaredinv = t.square().add(QM31::one()).inverse(); //(1+t^2)^-1
        
        script! {
            { t.double().mul(oneplustsquaredinv) }
            { QM31::one().add(t.square().neg()).mul(oneplustsquaredinv) }
        }
    }
}

#[cfg(test)]
mod test {
    use std::ops::{Add, Mul, Neg};

    use bitvm::treepp::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_u31_or_u30::{u31ext_equalverify, QM31 as QM31Gadget};

    use crate::{channel_extract::{Extractor, ExtractorGadget}, circle_secure::bitcoin_script::CirclePointSecureGadget, math::{Field, M31, QM31}};

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
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    //TODO: test that get_random_point() verifies the hints, not only that it correctly computes the value
    #[test]
    fn test_get_random_point(){
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut channel_digest = vec![0u8; 32];
        prng.fill_bytes(&mut channel_digest);

        let hash: [u8; 32] = channel_digest.as_slice().try_into().unwrap();
        let (t, hint_t) = Extractor::extract_qm31(&hash);

        let x=t.square().add(QM31::one()).inverse().mul(QM31::one().add(t.square().neg())); //(1+t^2)^-1 * (1-t^2)
        let y = t.square().add(QM31::one()).inverse().mul(QM31::one().double().mul(t)); // (1+t^2)^-1 * 2 * t

        let script = script! {
            //{ CirclePointSecureGadget::push_random_point_hint(channel_digest.clone()) }
            { ExtractorGadget::push_hint_qm31(&hint_t) }
            { hash.to_vec() }

            { CirclePointSecureGadget::get_random_point() }
            OP_DROP OP_DROP OP_DROP OP_DROP

            //{ channel_digest.clone() } //check channel'
            //OP_SHA256
            //OP_EQUALVERIFY // checking that indeed channel' = sha256(channel)
            //{ y } //check y
            //{ u31ext_equalverify::<QM31Gadget>() }
            //{ x } //check x
            //{ u31ext_equalverify::<QM31Gadget>() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}