use bitvm::treepp::pushable::{Builder, Pushable};
use math::{CM31, M31, QM31};

pub mod channel;
pub mod channel_commit;
pub mod channel_extract;
pub mod circle;
pub mod circle_secure;
pub mod fri;
pub mod math;
pub mod merkle_tree;
pub mod pow;
pub mod twiddle_merkle_tree;
pub mod utils;

impl Pushable for M31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        self.0.bitcoin_script_push(builder)
    }
}

impl Pushable for CM31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let builder = self.1.bitcoin_script_push(builder);
        self.0.bitcoin_script_push(builder)
    }
}

impl Pushable for QM31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let builder = self.1.bitcoin_script_push(builder);
        self.0.bitcoin_script_push(builder)
    }
}

#[cfg(test)]
mod test {
    use crate::channel::Channel;
    use crate::circle::CirclePoint;
    use crate::fri;
    use crate::math::Field;
    use crate::twiddle_merkle_tree::TWIDDLE_MERKLE_TREE_ROOT_4;
    use crate::utils::permute_eval;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_cfri_main() {
        // Prepare a low degree evaluation
        let logn = 5;
        let p = CirclePoint::subgroup_gen(logn + 1);

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut channel_init_state = [0u8; 32];
        channel_init_state.iter_mut().for_each(|v| *v = prng.gen());

        // Note: Add another .square() to make the proof fail.
        let evaluation = (0..(1 << logn))
            .map(|i| (p.mul(i * 2 + 1).x.square().square() + 1.into()).into())
            .collect();
        let evaluation = permute_eval(evaluation);

        // FRI.
        let proof = fri::fri_prove(&mut Channel::new(channel_init_state), evaluation);
        fri::fri_verify(
            &mut Channel::new(channel_init_state),
            logn,
            proof,
            TWIDDLE_MERKLE_TREE_ROOT_4,
        );
    }
}
