use crate::channel_commit::Commitment;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::fields::QM31;

pub struct Channel {
    channel: crate::channel::Channel,
}
impl Channel {
    pub fn new(seed: u64) -> Self {
        let mut prng = ChaCha20Rng::seed_from_u64(seed);

        let mut a = [0u8; 32];
        a.iter_mut().for_each(|v| *v = prng.gen());

        Self {
            channel: crate::channel::Channel::new(a),
        }
    }
    pub fn mix_with_commitment(&mut self, commitment: &Commitment) {
        self.channel.mix_with_commitment(commitment)
    }

    pub fn mix_with_el(&mut self, commitment: &QM31) {
        self.channel.mix_with_el(commitment);
    }

    pub fn draw_element(&mut self) -> QM31 {
        let (res, _) = self.channel.draw_element();
        res
    }
    pub fn draw_5queries(&mut self, logn: usize) -> [usize; 5] {
        let (v, _) = self.channel.draw_5queries(logn);

        let res = [
            v[0].0 as usize,
            v[1].0 as usize,
            v[2].0 as usize,
            v[3].0 as usize,
            v[4].0 as usize,
        ];
        res
    }
}
