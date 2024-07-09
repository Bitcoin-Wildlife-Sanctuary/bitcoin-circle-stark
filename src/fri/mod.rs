use crate::channel::{ChannelWithHint, DrawHints};
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::FieldExpOps;
use stwo_prover::core::queries::Queries;

mod bitcoin_script;
use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;

/// A trait for generating the queries with hints.
pub trait QueriesWithHint: Sized {
    /// Generate the queries and the corresponding hints.
    fn generate_with_hints(
        channel: &mut impl ChannelWithHint,
        log_domain_size: u32,
        n_queries: usize,
    ) -> (Self, DrawHints);
}

impl QueriesWithHint for Queries {
    fn generate_with_hints(
        channel: &mut impl ChannelWithHint,
        log_domain_size: u32,
        n_queries: usize,
    ) -> (Self, DrawHints) {
        let res = channel.draw_queries_and_hints(n_queries, log_domain_size as usize);
        (
            Self {
                positions: res.0.into_iter().collect(),
                log_domain_size,
            },
            res.1,
        )
    }
}

#[derive(Default, Clone)]
/// Hint for inverting a field element.
pub struct FieldInversionHint {
    /// The computed inverse.
    pub inverse: M31,
}

impl From<M31> for FieldInversionHint {
    fn from(value: M31) -> Self {
        Self {
            inverse: value.inverse(),
        }
    }
}

impl Pushable for &FieldInversionHint {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        self.inverse.bitcoin_script_push(builder)
    }
}

impl Pushable for FieldInversionHint {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        (&self).bitcoin_script_push(builder)
    }
}
