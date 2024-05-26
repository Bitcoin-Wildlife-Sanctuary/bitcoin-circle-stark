use crate::treepp::*;
use rust_bitcoin_m31::{
    m31_add_n31, m31_sub, push_m31_one, push_n31_one, push_qm31_one, qm31_double, qm31_dup,
    qm31_equalverify, qm31_from_bottom, qm31_mul, qm31_neg, qm31_roll, qm31_rot, qm31_square,
    qm31_sub, qm31_swap,
};
use std::ops::{Add, Mul, Neg};

use crate::{
    channel::ChannelGadget,
    math::{Field, QM31},
};

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
            qm31_square
            qm31_double
            push_qm31_one
            qm31_sub
        }
    }

    // Samples a random point over the projective line, see Lemma 1 in https://eprint.iacr.org/2024/278.pdf
    //
    // input:
    //  w - qm31 hint (5 elements)
    //  x - (1-t^2)/(1+t^2), where t is extracted from channel (4 elements)
    //  y - 2t/(1+t^2), where t is extracted from channel (4 elements)
    //  channel
    //
    // output:
    //  channel'=sha256(channel)
    //  x
    //  y
    // where (x,y) - random point on C(QM31) satisfying x^2+y^2=1 (8 elements)
    pub fn get_random_point() -> Script {
        script! {
            { ChannelGadget::squeeze_element_using_hint() }
            // stack: x, y, channel', t

            // compute t^2 from t
            qm31_dup
            qm31_square

            // compute t^2 - 1
            qm31_dup
            push_m31_one
            m31_sub // a trick

            // compute t^2 + 1
            qm31_swap
            push_n31_one
            m31_add_n31
            qm31_dup

            // stack: x, y, channel', t, t^2 - 1, t^2 + 1, t^2 + 1

            // pull the hint x and verify
            qm31_from_bottom
            qm31_dup
            qm31_rot
            qm31_mul
            qm31_neg
            { qm31_roll(3) }
            qm31_equalverify

            // stack: y, channel', t, t^2 + 1, x

            // pull the hint y
            qm31_from_bottom
            qm31_dup
            { qm31_roll(3) }
            qm31_mul
            { qm31_roll(3) }
            qm31_double
            qm31_equalverify
        }
    }

    pub fn push_random_point_hint(t: QM31) -> Script {
        let one_plus_tsquared_inv = t.square().add(QM31::one()).inverse();

        script! {
            { QM31::one().add(t.square().neg()).mul(one_plus_tsquared_inv) } // x = (1 - t^2) / (1 + t^2)
            { t.double().mul(one_plus_tsquared_inv) } // y = 2t / (1 + t^2)
        }
    }
}

#[cfg(test)]
mod test {
    use std::ops::{Add, Mul, Neg};

    use crate::treepp::*;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;

    use crate::{
        channel::Channel,
        channel_extract::ExtractorGadget,
        circle_secure::bitcoin_script::CirclePointSecureGadget,
        math::{Field, M31, QM31},
    };

    #[test]
    fn test_double_x() {
        let double_x_script = CirclePointSecureGadget::double_x();
        println!(
            "CirclePointSecure.double_x() = {} bytes",
            double_x_script.len()
        );

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
                { double_x_script.clone() }
                { double_a }
                qm31_equalverify
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_get_random_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let get_random_point_script = CirclePointSecureGadget::get_random_point();
        println!(
            "CirclePointSecure.get_random_point() = {} bytes",
            get_random_point_script.len()
        );

        let mut a = [0u8; 32];
        a.iter_mut().for_each(|v| *v = prng.gen());

        let mut channel = Channel::new(a);
        let (t, hint_t) = channel.draw_element();

        let c = channel.state;

        let x = t
            .square()
            .add(QM31::one())
            .inverse()
            .mul(QM31::one().add(t.square().neg())); //(1+t^2)^-1 * (1-t^2)
        let y = t
            .square()
            .add(QM31::one())
            .inverse()
            .mul(QM31::one().double().mul(t)); // (1+t^2)^-1 * 2 * t

        let script = script! {
            { ExtractorGadget::push_hint_qm31(&hint_t) }
            { CirclePointSecureGadget::push_random_point_hint(t.clone()) }
            { a.to_vec() }
            { get_random_point_script.clone() }
            { y } // check y
            qm31_equalverify
            { x } // check x
            qm31_equalverify
            { c.to_vec() } // check channel'
            OP_EQUALVERIFY // checking that indeed channel' = sha256(channel)
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
