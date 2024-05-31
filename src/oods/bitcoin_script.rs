use crate::channel::ChannelGadget;
use crate::treepp::*;
use rust_bitcoin_m31::{
    m31_add_n31, m31_sub, push_m31_one, push_n31_one, qm31_double, qm31_dup, qm31_equalverify,
    qm31_from_bottom, qm31_mul, qm31_neg, qm31_roll, qm31_rot, qm31_square, qm31_swap,
};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::qm31::QM31;

/// Gadget for out-of-domain sampling.
pub struct OODSGadget;

impl OODSGadget {
    /// Samples a random point over the projective line, see Lemma 1 in https://eprint.iacr.org/2024/278.pdf
    ///
    /// hint:
    ///  w - qm31 hint (5 elements)
    ///
    /// input:
    ///  x - (1-t^2)/(1+t^2), where t is extracted from channel (4 elements)
    ///  y - 2t/(1+t^2), where t is extracted from channel (4 elements)
    ///  channel
    ///
    /// output:
    ///  channel'=sha256(channel)
    ///  x
    ///  y
    /// where (x,y) - random point on C(QM31) satisfying x^2+y^2=1 (8 elements)
    pub fn get_random_point() -> Script {
        script! {
            { ChannelGadget::squeeze_qm31_using_hint() }
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

    /// Push the hint for sampling a random circle curve point over qm31.
    pub fn push_random_point_hint(p: &CirclePoint<QM31>) -> Script {
        script! {
            { p.x }
            { p.y }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::channel::{Channel, ExtractorGadget};
    use crate::oods::{OODSGadget, OODS};
    use crate::treepp::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;

    #[test]
    fn test_get_random_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let get_random_point_script = OODSGadget::get_random_point();
        println!(
            "OODS.get_random_point() = {} bytes",
            get_random_point_script.len()
        );

        let mut a = [0u8; 32];
        a.iter_mut().for_each(|v| *v = prng.gen());

        let mut channel = Channel::new(a);

        let (p, hint_t) = OODS::get_random_point(&mut channel);

        let c = channel.state;

        let script = script! {
            { ExtractorGadget::push_hint_qm31(&hint_t) }
            { OODSGadget::push_random_point_hint(&p) }
            { a.to_vec() }
            { get_random_point_script.clone() }
            { p.y } // check y
            qm31_equalverify
            { p.x } // check x
            qm31_equalverify
            { c.to_vec() } // check channel'
            OP_EQUALVERIFY // checking that indeed channel' = sha256(channel)
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
