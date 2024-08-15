//! The bitcoin-circle-stark crate implements a number of Bitcoin script gadgets for
//! a stwo proof verifier.

#![deny(missing_docs)]

use crate::treepp::pushable::{Builder, Pushable};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

/// Module for AIR-related features.
pub mod air;
/// Module for absorbing and squeezing of the channel.
pub mod channel;
/// Module for the circle curve over the qm31 field.
pub mod circle;
/// Module for constraints over the circle curve
pub mod constraints;
/// Module for FRI.
pub mod fri;
/// Module for the Merkle tree.
pub mod merkle_tree;
/// Module for out-of-domain sampling.
pub mod oods;
/// Module for PoW.
pub mod pow;
/// Module for the precomputed data Merkle tree.
pub mod precomputed_merkle_tree;
/// Module for test utils.
pub mod tests_utils;
/// Module for utility functions.
pub mod utils;

#[allow(missing_docs)]
pub mod treepp {
    pub use bitcoin_script::{define_pushable, script};

    pub use bitcoin_scriptexec::{convert_to_witness, get_final_stack};

    #[cfg(test)]
    pub use bitcoin_scriptexec::{execute_script, execute_script_with_witness_unlimited_stack};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

impl Pushable for M31 {
    fn bitcoin_script_push(&self, builder: Builder) -> Builder {
        self.0.bitcoin_script_push(builder)
    }
}

impl Pushable for CM31 {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self.1.bitcoin_script_push(builder);
        builder = self.0.bitcoin_script_push(builder);
        builder
    }
}

impl Pushable for QM31 {
    fn bitcoin_script_push(&self, builder: Builder) -> Builder {
        let mut builder = self.1 .1.bitcoin_script_push(builder);
        builder = self.1 .0.bitcoin_script_push(builder);
        builder = self.0 .1.bitcoin_script_push(builder);
        self.0 .0.bitcoin_script_push(builder)
    }
}

impl Pushable for Sha256Hash {
    fn bitcoin_script_push(&self, builder: Builder) -> Builder {
        self.as_ref().to_vec().bitcoin_script_push(builder)
    }
}

impl Pushable for CirclePoint<QM31> {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self.x.bitcoin_script_push(builder);
        builder = self.y.bitcoin_script_push(builder);
        builder
    }
}

#[allow(non_snake_case)]
/// Pseudo opcode for retrieving a hint element from the bottom of the stack.
pub fn OP_HINT() -> treepp::Script {
    use treepp::*;
    script! {
        OP_DEPTH OP_1SUB OP_ROLL
    }
}

#[cfg(test)]
mod test {
    use crate::treepp::{
        pushable::{Builder, Pushable},
        *,
    };
    use crate::utils::get_rand_qm31;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_prover::core::fields::cm31::CM31;
    use stwo_prover::core::fields::m31::M31;

    #[test]
    fn test_pushable() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let m31 = M31::reduce(prng.next_u64());
        let cm31 = CM31::from_m31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64()));
        let qm31 = get_rand_qm31(&mut prng);

        let mut builder = Builder::new();
        builder = m31.bitcoin_script_push(builder);
        assert_eq!(script! { {m31} }.as_bytes(), builder.as_bytes());

        let mut builder = Builder::new();
        builder = cm31.bitcoin_script_push(builder);
        assert_eq!(script! { {cm31} }.as_bytes(), builder.as_bytes());

        let mut builder = Builder::new();
        builder = qm31.bitcoin_script_push(builder);
        assert_eq!(script! { {qm31} }.as_bytes(), builder.as_bytes());
    }
}
