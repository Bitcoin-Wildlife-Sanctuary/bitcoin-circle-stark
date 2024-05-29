use crate::treepp::pushable::{Builder, Pushable};
use bitcoin::script::PushBytesBuf;
use core::ops::Neg;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

mod bitcoin_script;
pub use bitcoin_script::*;

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

/// An extractor for field elements.
pub struct Extractor;
impl Extractor {
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

    /// Extract a m31 element from a hash.
    pub fn extract_m31(hash: &[u8; 32]) -> (M31, ExtractionM31) {
        let (res, hint) = Self::extract_common(hash);

        let mut hint_bytes = [0u8; 28];
        hint_bytes.copy_from_slice(&hash[4..]);

        (res, ExtractionM31(hint, hint_bytes))
    }

    /// Extract a cm31 element from a hash.
    pub fn extract_cm31(hash: &[u8; 32]) -> (CM31, ExtractionCM31) {
        let (res_1, hint_1) = Self::extract_common(hash);
        let (res_2, hint_2) = Self::extract_common(&hash[4..]);

        let mut hint_bytes = [0u8; 24];
        hint_bytes.copy_from_slice(&hash[8..]);

        (
            CM31(res_1, res_2),
            ExtractionCM31((hint_1, hint_2), hint_bytes),
        )
    }

    /// Extract a qm31 element from a hash.
    pub fn extract_qm31(hash: &[u8; 32]) -> (QM31, ExtractionQM31) {
        let (res_1, hint_1) = Self::extract_common(hash);
        let (res_2, hint_2) = Self::extract_common(&hash[4..]);
        let (res_3, hint_3) = Self::extract_common(&hash[8..]);
        let (res_4, hint_4) = Self::extract_common(&hash[12..]);

        let mut hint_bytes = [0u8; 16];
        hint_bytes.copy_from_slice(&hash[16..]);

        (
            QM31(CM31(res_1, res_2), CM31(res_3, res_4)),
            ExtractionQM31((hint_1, hint_2, hint_3, hint_4), hint_bytes),
        )
    }

    /// Extract five m31 elements from a hash.
    pub fn extract_5m31(hash: &[u8; 32]) -> ([M31; 5], Extraction5M31) {
        let (res_1, hint_1) = Self::extract_common(hash);
        let (res_2, hint_2) = Self::extract_common(&hash[4..]);
        let (res_3, hint_3) = Self::extract_common(&hash[8..]);
        let (res_4, hint_4) = Self::extract_common(&hash[12..]);
        let (res_5, hint_5) = Self::extract_common(&hash[16..]);

        let mut hint_bytes = [0u8; 12];
        hint_bytes.copy_from_slice(&hash[20..]);

        (
            [res_1, res_2, res_3, res_4, res_5],
            Extraction5M31((hint_1, hint_2, hint_3, hint_4, hint_5), hint_bytes),
        )
    }
}

/// Extraction hint for a m31 element.
pub struct ExtractionM31(pub ExtractorHint, pub [u8; 28]);
/// Extraction hint for a cm31 element.
pub struct ExtractionCM31(pub (ExtractorHint, ExtractorHint), pub [u8; 24]);
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
