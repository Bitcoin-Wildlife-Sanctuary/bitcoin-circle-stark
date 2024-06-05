use crate::channel::Sha256Channel;
use crate::channel::{ChannelWithHint, DrawHints};
use num_traits::One;
use std::ops::{Add, Mul, Neg};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::{Field, FieldExpOps};

mod bitcoin_script;
use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;

/// An out-of-domain sampling implementation.
pub trait OODS: Sized {
    /// Obtain a random point from the channel and its hint.
    fn get_random_point_with_hint(channel: &mut Sha256Channel) -> (Self, OODSHint);
}

impl OODS for CirclePoint<QM31> {
    fn get_random_point_with_hint(channel: &mut Sha256Channel) -> (Self, OODSHint) {
        let (t, hint) = channel.draw_felt_and_hints();

        let one_plus_tsquared_inv = t.square().add(QM31::one()).inverse();

        let x = QM31::one().add(t.square().neg()).mul(one_plus_tsquared_inv);
        let y = t.double().mul(one_plus_tsquared_inv);

        (CirclePoint { x, y }, OODSHint { x, y, hint })
    }
}

/// Hint for out-of-domain sampling.
#[derive(Clone)]
pub struct OODSHint {
    /// The x coordinate.
    pub x: QM31,
    /// The y coordinate.
    pub y: QM31,
    /// Hint for extracting t from the hash.
    pub hint: DrawHints<4>,
}

impl Pushable for OODSHint {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        builder = self.hint.bitcoin_script_push(builder);
        builder = self.x.bitcoin_script_push(builder);
        self.y.bitcoin_script_push(builder)
    }
}
