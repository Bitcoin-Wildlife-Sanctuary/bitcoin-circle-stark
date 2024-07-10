mod bitcoin_script;

use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;
use stwo_prover::core::fields::qm31::SecureField;

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
