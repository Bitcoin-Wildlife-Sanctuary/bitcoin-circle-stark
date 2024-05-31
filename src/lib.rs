//! The bitcoin-circle-stark crate implements a number of Bitcoin script gadgets for
//! a stwo proof verifier.

#![deny(missing_docs)]

use crate::treepp::pushable::{Builder, Pushable};
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

/// Module for absorbing and squeezing of the channel.
pub mod channel;
/// Module for committing data.
pub mod channel_commit;
/// Module for extracting elements from a channel.
pub mod channel_extract;
/// Module for the circle curve over the qm31 field.
pub mod circle;
/// Module for constraints over the circle curve
pub mod constraints;
/// Module for Fibonacci end-to-end test.
pub mod fibonacci;
/// Module for FRI.
pub mod fri;
/// Module for the field and group arithmetics.
pub mod math;
/// Module for the Merkle tree.
pub mod merkle_tree;
/// Module for out-of-domain sampling.
pub mod oods;
/// Module for PoW.
pub mod pow;
/// Module for the twiddle Merkle tree.
pub mod twiddle_merkle_tree;
/// Module for utility functions.
pub mod utils;

pub(crate) mod treepp {
    pub use bitcoin_script::{define_pushable, script};
    #[cfg(test)]
    pub use bitcoin_scriptexec::{convert_to_witness, execute_script};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

impl Pushable for M31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        self.0.bitcoin_script_push(builder)
    }
}

impl Pushable for CM31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let builder = self.1.bitcoin_script_push(builder);
        self.0.bitcoin_script_push(builder)
    }
}

impl Pushable for QM31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let builder = self.1.bitcoin_script_push(builder);
        self.0.bitcoin_script_push(builder)
    }
}

#[cfg(test)]
mod test {
    use crate::channel::Channel;
    use crate::fri;
    use crate::twiddle_merkle_tree::TWIDDLE_MERKLE_TREE_ROOT_4;
    use crate::utils::permute_eval;
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_prover::core::circle::CirclePointIndex;
    use stwo_prover::core::fields::m31::M31;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fields::FieldExpOps;

    #[test]
    fn test_cfri_main() {
        // Prepare a low degree evaluation
        let logn = 5;
        let p = CirclePointIndex::subgroup_gen(logn as u32 + 1).to_point();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut channel_init_state = [0u8; 32];
        channel_init_state.iter_mut().for_each(|v| *v = prng.gen());

        // Note: Add another .square() to make the proof fail.
        let evaluation = (0..(1 << logn))
            .map(|i| (p.mul(i * 2 + 1).x.square().square() + M31::one()).into())
            .collect::<Vec<QM31>>();
        let evaluation = permute_eval(evaluation);

        // FRI.
        let proof = fri::fri_prove(&mut Channel::new(channel_init_state), evaluation);
        fri::fri_verify(
            &mut Channel::new(channel_init_state),
            logn,
            proof,
            TWIDDLE_MERKLE_TREE_ROOT_4,
        );
    }
}
