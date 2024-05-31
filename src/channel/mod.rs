use crate::utils::{hash_qm31, trim_m31};
use bitcoin::script::PushBytesBuf;
use sha2::{Digest, Sha256};
use std::ops::Neg;
use stwo_prover::core::channel::Channel;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::{SecureField, QM31};

mod bitcoin_script;
use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;

/// A channel.
pub struct Sha256Channel {
    /// Current state of the channel.
    pub state: [u8; 32],
}

impl Channel for Sha256Channel {
    type Digest = [u8; 32];
    const BYTES_PER_HASH: usize = 32;

    fn new(digest: Self::Digest) -> Self {
        Self { state: digest }
    }

    fn get_digest(&self) -> Self::Digest {
        self.state
    }

    fn mix_digest(&mut self, digest: Self::Digest) {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, digest);
        Digest::update(&mut hasher, self.state);
        self.state.copy_from_slice(hasher.finalize().as_slice());
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        for felt in felts.iter() {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, hash_qm31(felt));
            Digest::update(&mut hasher, self.state);
            self.state.copy_from_slice(hasher.finalize().as_slice());
        }
    }

    fn mix_nonce(&mut self, nonce: u64) {
        // mix_nonce is called during PoW. However, later we plan to replace it by a Bitcoin block
        // inclusion proof, then this function would never be called.

        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&nonce.to_le_bytes());

        self.mix_digest(hash);
    }

    fn draw_felt(&mut self) -> SecureField {
        let mut extract = [0u8; 32];

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.state);
        Digest::update(&mut hasher, [0u8]);
        extract.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.state);
        self.state.copy_from_slice(hasher.finalize().as_slice());

        let (res_1, _) = Self::extract_common(&extract);
        let (res_2, _) = Self::extract_common(&extract[4..]);
        let (res_3, _) = Self::extract_common(&extract[8..]);
        let (res_4, _) = Self::extract_common(&extract[12..]);

        QM31(CM31(res_1, res_2), CM31(res_3, res_4))
    }

    fn draw_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        let mut res = vec![];
        for _ in 0..n_felts {
            res.push(self.draw_felt());
        }
        res
    }

    fn draw_random_bytes(&mut self) -> Vec<u8> {
        let mut extract = [0u8; 32];

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.state);
        Digest::update(&mut hasher, [0u8]);
        extract.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.state);
        self.state.copy_from_slice(hasher.finalize().as_slice());

        extract.to_vec()
    }
}

impl Sha256Channel {
    /// Initialize a new channel.
    pub fn new(hash: [u8; 32]) -> Self {
        Self { state: hash }
    }

    /// Draw one qm31 and compute the hints.
    pub fn draw_felt_and_hints(&mut self) -> (QM31, ExtractionQM31) {
        let mut extract = [0u8; 32];

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.state);
        Digest::update(&mut hasher, [0u8]);
        extract.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.state);
        self.state.copy_from_slice(hasher.finalize().as_slice());

        let (res_1, hint_1) = Self::extract_common(&extract);
        let (res_2, hint_2) = Self::extract_common(&extract[4..]);
        let (res_3, hint_3) = Self::extract_common(&extract[8..]);
        let (res_4, hint_4) = Self::extract_common(&extract[12..]);

        let mut hint_bytes = [0u8; 16];
        hint_bytes.copy_from_slice(&extract[16..]);

        (
            QM31(CM31(res_1, res_2), CM31(res_3, res_4)),
            ExtractionQM31((hint_1, hint_2, hint_3, hint_4), hint_bytes),
        )
    }

    /// Draw five queries and compute the hints.
    pub fn draw_5queries(&mut self, logn: usize) -> ([usize; 5], Extraction5M31) {
        let mut extract = [0u8; 32];

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.state);
        Digest::update(&mut hasher, [0u8]);
        extract.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.state);
        self.state.copy_from_slice(hasher.finalize().as_slice());

        let (res_1, hint_1) = Self::extract_common(&extract);
        let (res_2, hint_2) = Self::extract_common(&extract[4..]);
        let (res_3, hint_3) = Self::extract_common(&extract[8..]);
        let (res_4, hint_4) = Self::extract_common(&extract[12..]);
        let (res_5, hint_5) = Self::extract_common(&extract[16..]);

        let mut hint_bytes = [0u8; 12];
        hint_bytes.copy_from_slice(&extract[20..]);

        let mut res = [res_1, res_2, res_3, res_4, res_5];
        let hint = Extraction5M31((hint_1, hint_2, hint_3, hint_4, hint_5), hint_bytes);

        for v in res.iter_mut() {
            v.0 = trim_m31(v.0, logn);
        }

        (
            [
                res[0].0 as usize,
                res[1].0 as usize,
                res[2].0 as usize,
                res[3].0 as usize,
                res[4].0 as usize,
            ],
            hint,
        )
    }

    fn extract_common(hash: &[u8]) -> (M31, ExtractorHint) {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&hash[0..4]);

        let mut res = u32::from_le_bytes(bytes);
        res &= 0x7fffffff;

        let hint = if bytes[3] & 0x80 != 0 {
            if res == 0 {
                ExtractorHint::NegativeZero
            } else {
                ExtractorHint::Other((res as i64).neg())
            }
        } else {
            ExtractorHint::Other(res as i64)
        };

        res = res.saturating_sub(1);

        (M31::from(res), hint)
    }
}

/// Basic hint structure for extracting a single qm31 element.
#[derive(Clone, Copy)]
pub enum ExtractorHint {
    /// negative zero (will be represented by 0x80).
    NegativeZero,
    /// any Bitcoin integer other than the negative zero.
    Other(i64),
}

impl Pushable for ExtractorHint {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        match self {
            ExtractorHint::NegativeZero => builder.push_slice(PushBytesBuf::from([0x80])),
            ExtractorHint::Other(v) => builder.push_int(v),
        }
    }
}

/// Extraction hint for a qm31 element.
pub struct ExtractionQM31(
    pub (ExtractorHint, ExtractorHint, ExtractorHint, ExtractorHint),
    pub [u8; 16],
);

/// Extraction hint for five m31 elements.
pub struct Extraction5M31(
    pub  (
        ExtractorHint,
        ExtractorHint,
        ExtractorHint,
        ExtractorHint,
        ExtractorHint,
    ),
    pub [u8; 12],
);
