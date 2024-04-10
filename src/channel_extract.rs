use crate::cfri::fields::{CM31, M31, QM31};
use bitvm::treepp::*;
use core::ops::Neg;

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

pub struct ExtractorGadget;
impl ExtractorGadget {
    pub fn push_hint_m31(e: &ExtractionM31) -> Script {
        script! {
            { e.0 }
            { e.1.to_vec() }
        }
    }

    pub fn push_hint_cm31(e: &ExtractionCM31) -> Script {
        script! {
            { e.0.0 }
            { e.0.1 }
            { e.1.to_vec() }
        }
    }

    pub fn push_hint_qm31(e: &ExtractionQM31) -> Script {
        script! {
            { e.0.0 }
            { e.0.1 }
            { e.0.2 }
            { e.0.3 }
            { e.1.to_vec() }
        }
    }

    pub fn push_hint_5m31(e: &Extraction5M31) -> Script {
        script! {
            { e.0.0 }
            { e.0.1 }
            { e.0.2 }
            { e.0.3 }
            { e.0.4 }
            { e.1.to_vec() }
        }
    }

    fn reconstruct() -> Script {
        script! {
            OP_DUP OP_ABS OP_2DUP OP_TOALTSTACK
            OP_EQUAL
            OP_IF
                OP_SIZE 4 OP_LESSTHAN OP_IF OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT OP_ENDIF
            OP_ELSE
                OP_SIZE 4 OP_LESSTHAN OP_IF OP_ABS OP_PUSHBYTES_1 OP_LEFT OP_CAT OP_ENDIF
            OP_ENDIF
            for _ in 0..3 {
                OP_SIZE 4 OP_LESSTHAN OP_IF OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT OP_ENDIF
            }
        }
    }

    pub fn unpack_m31() -> Script {
        script! {
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DEPTH OP_1SUB OP_ROLL

            OP_SWAP
            { Self::reconstruct() }

            OP_SWAP OP_CAT
            OP_EQUALVERIFY
            OP_FROMALTSTACK
        }
    }

    pub fn unpack_cm31() -> Script {
        script! {
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DEPTH OP_1SUB OP_ROLL

            OP_ROT
            { Self::reconstruct() }

            OP_ROT
            { Self::reconstruct() }

            OP_CAT
            OP_SWAP OP_CAT

            OP_EQUALVERIFY
            OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP
        }
    }

    pub fn unpack_qm31() -> Script {
        script! {
            for _ in 0..5 {
                OP_DEPTH OP_1SUB OP_ROLL
            }


            for _ in 0..4 {
                4 OP_ROLL
                { Self::reconstruct() }
            }

            OP_CAT OP_CAT OP_CAT
            OP_SWAP OP_CAT

            OP_EQUALVERIFY
            OP_FROMALTSTACK OP_FROMALTSTACK
            OP_FROMALTSTACK OP_FROMALTSTACK
            OP_SWAP
            2 OP_ROLL
            3 OP_ROLL
        }
    }

    pub fn unpack_5m31() -> Script {
        script! {
            for _ in 0..6 {
                OP_DEPTH OP_1SUB OP_ROLL
            }

            for _ in 0..5 {
                5 OP_ROLL
                { Self::reconstruct() }
            }

            OP_CAT OP_CAT OP_CAT OP_CAT
            OP_SWAP OP_CAT

            OP_EQUALVERIFY
            OP_FROMALTSTACK OP_FROMALTSTACK
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            OP_SWAP
            2 OP_ROLL
            3 OP_ROLL
            4 OP_ROLL
        }
    }
}

#[cfg(test)]
mod test {
    use crate::channel_extract::{Extractor, ExtractorGadget};
    use bitcoin_script::script;
    use bitvm::treepp::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_unpack_m31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let unpack_script = ExtractorGadget::unpack_m31();
        println!("M31.from_hash() = {} bytes", unpack_script.len());

        let mut hash = [0u8; 32];
        for i in 0..32 {
            hash[i] = prng.gen();
        }
        hash[3] |= 0x80;

        let (elem, e) = Extractor::extract_m31(&hash);

        let script = script! {
            { ExtractorGadget::push_hint_m31(&e) }
            { hash.to_vec() }
            { unpack_script.clone() }
            { elem }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        hash[3] = 0;
        hash[2] &= 0x7f;
        let (elem, e) = Extractor::extract_m31(&hash);

        let script = script! {
            { ExtractorGadget::push_hint_m31(&e) }
            { hash.to_vec() }
            { unpack_script.clone() }
            { elem }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        hash[2] = 0;
        hash[1] &= 0x7f;
        let (elem, e) = Extractor::extract_m31(&hash);

        let script = script! {
            { ExtractorGadget::push_hint_m31(&e) }
            { hash.to_vec() }
            { unpack_script.clone() }
            { elem }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        hash[1] = 0;
        hash[0] &= 0x7f;
        let (elem, e) = Extractor::extract_m31(&hash);

        let script = script! {
            { ExtractorGadget::push_hint_m31(&e) }
            { hash.to_vec() }
            { unpack_script.clone() }
            { elem }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        hash[0] = 0;
        let (elem, e) = Extractor::extract_m31(&hash);

        let script = script! {
            { ExtractorGadget::push_hint_m31(&e) }
            { hash.to_vec() }
            { unpack_script.clone() }
            { elem }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        let mut hash = [0u8; 32];
        for i in 0..32 {
            hash[i] = prng.gen();
        }
        hash[3] |= 0x80;
        hash[2] = 0;

        let (elem, e) = Extractor::extract_m31(&hash);

        let script = script! {
            { ExtractorGadget::push_hint_m31(&e) }
            { hash.to_vec() }
            { unpack_script.clone() }
            { elem }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_unpack_cm31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let unpack_script = ExtractorGadget::unpack_cm31();
        println!("CM31.from_hash() = {} bytes", unpack_script.len());

        for _ in 0..300 {
            let mut hash = [0u8; 32];
            for i in 0..32 {
                hash[i] = prng.gen();
            }

            let (elem, e) = Extractor::extract_cm31(&hash);

            let script = script! {
                { ExtractorGadget::push_hint_cm31(&e) }
                { hash.to_vec() }
                { unpack_script.clone() }
                { elem }
                OP_ROT OP_EQUALVERIFY
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_unpack_qm31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let unpack_script = ExtractorGadget::unpack_qm31();
        println!("QM31.from_hash() = {} bytes", unpack_script.len());

        for _ in 0..300 {
            let mut hash = [0u8; 32];
            for i in 0..32 {
                hash[i] = prng.gen();
            }

            let (elem, e) = Extractor::extract_qm31(&hash);

            let script = script! {
                { ExtractorGadget::push_hint_qm31(&e) }
                { hash.to_vec() }
                { unpack_script.clone() }
                { elem }
                4 OP_ROLL OP_EQUALVERIFY
                3 OP_ROLL OP_EQUALVERIFY
                OP_ROT OP_EQUALVERIFY
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_unpack_5m31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let unpack_script = ExtractorGadget::unpack_5m31();
        println!("5M31.from_hash() = {} bytes", unpack_script.len());

        for _ in 0..300 {
            let mut hash = [0u8; 32];
            for i in 0..32 {
                hash[i] = prng.gen();
            }

            let (elem, e) = Extractor::extract_5m31(&hash);

            let script = script! {
                { ExtractorGadget::push_hint_5m31(&e) }
                { hash.to_vec() }
                { unpack_script.clone() }
                { elem[4] } OP_EQUALVERIFY
                { elem[3] } OP_EQUALVERIFY
                { elem[2] } OP_EQUALVERIFY
                { elem[1] } OP_EQUALVERIFY
                { elem[0] } OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
