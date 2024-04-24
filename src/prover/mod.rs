// This folder contains reference code provided by Starkware, as a minimalistic example for FRI.

mod fft;
mod fri;
mod utils;

#[cfg(test)]
mod test {
    use crate::channel::Channel;
    use crate::circle::CirclePoint;
    use crate::fields::Field;
    use crate::prover::fri;
    use crate::prover::utils::permute_eval;
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
        fri::fri_verify(&mut Channel::new(channel_init_state), logn, proof);
    }
}
