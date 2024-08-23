mod bitcoin_script;

use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::ColumnVec;

#[derive(Clone)]
/// Hint for the two eval quotient results involved in the composition polynomial.
pub struct CompositionHint {
    /// A vector of the quotient evaluation result for each constraint.
    /// We do not set the number of constraints because different AIR would have different ones.
    pub constraint_eval_quotients_by_mask: Vec<SecureField>,
}

impl Pushable for CompositionHint {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        for elem in self.constraint_eval_quotients_by_mask.iter() {
            builder = elem.bitcoin_script_push(builder);
        }
        builder
    }
}

/// A helper function to shift points, but with signed masks.
pub fn shifted_signed_mask_points(
    mask: &ColumnVec<Vec<isize>>,
    domains: &[CanonicCoset],
    point: CirclePoint<SecureField>,
) -> ColumnVec<Vec<CirclePoint<SecureField>>> {
    mask.iter()
        .zip(domains.iter())
        .map(|(mask_entry, domain)| {
            let trace_step = CanonicCoset::new(domain.log_size()).step();
            mask_entry
                .iter()
                .map(|mask_item| point + trace_step.mul_signed(*mask_item).into_ef())
                .collect()
        })
        .collect()
}
