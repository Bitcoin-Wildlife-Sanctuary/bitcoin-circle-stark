use crate::utils::{num_to_bytes, trim_m31};
use bitcoin::script::PushBytesBuf;
use sha2::{Digest, Sha256};
use std::ops::Neg;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

mod bitcoin_script;
use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;

/// A channel.
pub struct Channel {
    /// Current state of the channel.
    pub state: [u8; 32],
}

impl Channel {
    /// Initialize a new channel.
    pub fn new(hash: [u8; 32]) -> Self {
        Self { state: hash }
    }

    /// Absorb a commitment.
    pub fn absorb_commitment(&mut self, commitment: &Commitment) {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, commitment.0);
        Digest::update(&mut hasher, self.state);
        self.state.copy_from_slice(hasher.finalize().as_slice());
    }

    /// Absorb a qm31 element.
    pub fn absorb_qm31(&mut self, el: &QM31) {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, Commitment::commit_qm31(*el).0);
        Digest::update(&mut hasher, self.state);
        self.state.copy_from_slice(hasher.finalize().as_slice());
    }

    /// Draw one qm31 and compute the hints.
    pub fn draw_qm31(&mut self) -> (QM31, ExtractionQM31) {
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

/// A commitment, which is a 32-byte SHA256 hash
#[derive(Clone, Default, Debug)]
pub struct Commitment(pub [u8; 32]);

impl Pushable for Commitment {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let mut buf = PushBytesBuf::new();
        buf.extend_from_slice(&self.0).unwrap();
        builder.push_slice(buf)
    }
}

impl Commitment {
    /// Commit a qm31 element.
    pub fn commit_qm31(v: QM31) -> Self {
        let mut res = Self::default();

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &num_to_bytes(v.0 .0));
        res.0.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, num_to_bytes(v.0 .1));
        Digest::update(&mut hasher, res.0);
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
