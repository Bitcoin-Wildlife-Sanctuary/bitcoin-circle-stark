use crate::utils::num_to_bytes;
use sha2::{Digest, Sha256};
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

mod bitcoin_script;
pub use bitcoin_script::*;

/// A commitment, which is a 32-byte SHA256 hash
#[derive(Clone, Default, Debug)]
pub struct Commitment(pub [u8; 32]);

impl Commitment {
    /// Commit a m31 element.
    pub fn commit_m31(v: M31) -> Self {
        let mut res = Self::default();

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &num_to_bytes(v));

        res.0.copy_from_slice(hasher.finalize().as_slice());

        res
    }

    /// Commit a cm31 element.
    pub fn commit_cm31(v: CM31) -> Self {
        let mut res = Self::default();

        let c1 = Self::commit_m31(v.0);
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, num_to_bytes(v.1));
        Digest::update(&mut hasher, c1.0);

        res.0.copy_from_slice(hasher.finalize().as_slice());

        res
    }

    /// Commit a qm31 element.
    pub fn commit_qm31(v: QM31) -> Self {
        let mut res = Self::default();

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, num_to_bytes(v.0 .1));
        Digest::update(&mut hasher, Self::commit_m31(v.0 .0).0);
        res.0.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, num_to_bytes(v.1 .0));
        Digest::update(&mut hasher, res.0);
        res.0.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, num_to_bytes(v.1 .1));
        Digest::update(&mut hasher, res.0);
        res.0.copy_from_slice(hasher.finalize().as_slice());

        res
    }
}
