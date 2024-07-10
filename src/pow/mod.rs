mod bitcoin_script;
pub use bitcoin_script::*;

use crate::treepp::pushable::{Builder, Pushable};
use sha2::{Digest, Sha256};
use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hash;

/// Compute the hash from a seed and a nonce.
pub fn hash_with_nonce(seed: &[u8], nonce: u64) -> Vec<u8> {
    let mut concat = seed.to_owned();
    concat.extend(nonce.to_le_bytes().to_vec());

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, concat);

    hasher.finalize().as_slice().to_vec()
}

/// A hint for PoW.
pub struct PoWHint {
    /// The PoW nonce.
    /// Note: with a nonce of only 64 bits, it is not possible to get 78 bit security here :)
    pub nonce: u64,
    /// The prefix of sha256(channel||nonce).
    pub prefix: Vec<u8>,
    /// The msb of sha256(channel||nonce) immediately before the zero prefix (if n_bits % 8 != 0).
    pub msb: Option<u8>,
}

impl PoWHint {
    /// Create the hint for verifying the PoW.
    /// It contains the nonce, the suffix, and the msb (if n_bits % 8 != 0).
    pub fn new(channel_digest: BWSSha256Hash, nonce: u64, n_bits: u32) -> Self {
        assert!(n_bits > 0);

        let digest = hash_with_nonce(channel_digest.as_ref(), nonce);
        let n_bits = n_bits as usize;

        if n_bits % 8 == 0 {
            Self {
                nonce,
                prefix: digest[..32 - (n_bits / 8)].to_vec(),
                msb: None,
            }
        } else {
            Self {
                nonce,
                prefix: digest[..32 - (n_bits + 8 - 1) / 8].to_vec(),
                msb: Some(digest[32 - (n_bits + 8 - 1) / 8]),
            }
        }
    }
}

impl Pushable for PoWHint {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self
            .nonce
            .to_le_bytes()
            .to_vec()
            .bitcoin_script_push(builder);
        builder = self.prefix.clone().bitcoin_script_push(builder);
        if let Some(msb) = self.msb {
            builder = msb.bitcoin_script_push(builder);
        }
        builder
    }
}

