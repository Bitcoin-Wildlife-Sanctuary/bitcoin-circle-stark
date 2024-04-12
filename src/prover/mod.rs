// This folder contains reference code provided by Starkware, as a minimalistic example for FRI.

mod channel;
pub(crate) mod circle;
mod fft;
mod fri;
mod utils;

#[cfg(test)]
mod test {
    use crate::fields::Field;
    use crate::prover::channel::Channel;
    use crate::prover::circle::CirclePoint;
    use crate::prover::fri;
    use crate::prover::utils::permute_eval;

    #[test]
    fn test_cfri_main() {
        // Prepare a low degree evaluation
        let logn = 5;
        let p = CirclePoint::subgroup_gen(logn + 1);
        // Note: Add another .square() to make the proof fail.
        let evaluation = (0..(1 << logn))
            .map(|i| (p.mul(i * 2 + 1).x.square().square() + 1.into()).into())
            .collect();
        let evaluation = permute_eval(evaluation);

        // FRI.
        let proof = fri::fri_prove(&mut Channel::new(0), evaluation);
        fri::fri_verify(&mut Channel::new(0), logn, proof);
    }
}
