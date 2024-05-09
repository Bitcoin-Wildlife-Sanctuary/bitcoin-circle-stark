use core::ops::Neg;

mod bitcoin_script;
use crate::math::{CM31, M31, QM31};
pub use bitcoin_script::*;

pub struct Extractor;
impl Extractor {
    fn extract_common(hash: &[u8]) -> (M31, i64) {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&hash[0..4]);

        let mut res = u32::from_le_bytes(bytes);
        res &= 0x7fffffff;

        let hint = if bytes[3] & 0x80 != 0 {
            (res as i64).neg()
        } else {
            res as i64
        };

        if res != 0 {
            res -= 1;
        }

        (M31::from(res), hint)
    }

    pub fn extract_m31(hash: &[u8; 32]) -> (M31, ExtractionM31) {
        let (res, hint) = Self::extract_common(hash);

        let mut hint_bytes = [0u8; 28];
        hint_bytes.copy_from_slice(&hash[4..]);

        (res, ExtractionM31(hint, hint_bytes))
    }

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

pub struct ExtractionM31(pub i64, pub [u8; 28]);
pub struct ExtractionCM31(pub (i64, i64), pub [u8; 24]);
pub struct ExtractionQM31(pub (i64, i64, i64, i64), pub [u8; 16]);
pub struct Extraction5M31(pub (i64, i64, i64, i64, i64), pub [u8; 12]);
