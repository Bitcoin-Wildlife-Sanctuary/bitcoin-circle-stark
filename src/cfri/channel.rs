use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

use crate::fields::{M31, QM31};

pub type Commitment = Vec<QM31>;

pub struct Channel {
    rng: StdRng,
}
impl Channel {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
        }
    }
    pub fn mix_with_commitment(&mut self, _commitment: &Commitment) {}
    pub fn mix_with_el(&mut self, _commitment: &QM31) {}
    pub fn draw_element(&mut self) -> QM31 {
        QM31::from_m31_array([
            M31::reduce(self.rng.next_u64()),
            M31::reduce(self.rng.next_u64()),
            M31::reduce(self.rng.next_u64()),
            M31::reduce(self.rng.next_u64()),
        ])
    }
    pub fn draw_query(&mut self, logn: usize) -> usize {
        self.rng.gen_range(0..(1 << logn))
    }
}
