use crate::channel::{ChannelWithHint, DrawHints};
use stwo_prover::core::queries::Queries;

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
