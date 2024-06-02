use crate::channel::Sha256Channel;
use crate::channel::{ChannelWithHint, DrawHints};
use num_traits::One;
use std::ops::{Add, Mul, Neg};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::{Field, FieldExpOps};

mod bitcoin_script;
pub use bitcoin_script::*;

/// An out-of-domain sampling implementation.
pub trait OODS: Sized {
    /// Obtain a random point from the channel and its hint.
    fn get_random_point_with_hint(channel: &mut Sha256Channel) -> (Self, DrawHints<4>);
}

impl OODS for CirclePoint<QM31> {
    fn get_random_point_with_hint(
        channel: &mut Sha256Channel,
    ) -> (CirclePoint<QM31>, DrawHints<4>) {
        let (t, hint) = channel.draw_felt_and_hints();

        let one_plus_tsquared_inv = t.square().add(QM31::one()).inverse();

        let x = QM31::one().add(t.square().neg()).mul(one_plus_tsquared_inv);
        let y = t.double().mul(one_plus_tsquared_inv);

        (CirclePoint { x, y }, hint)
    }
}
