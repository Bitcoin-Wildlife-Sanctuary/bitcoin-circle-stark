use crate::channel_extract::{Extraction5M31, ExtractionCM31, ExtractionM31, ExtractionQM31};
use bitvm::treepp::*;

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
            OP_DUP OP_ABS
            OP_DUP OP_TOALTSTACK

            OP_SIZE 4 OP_LESSTHAN
            OP_IF
                OP_DUP OP_ROT
                OP_EQUAL OP_TOALTSTACK

                // stack: abs(a)
                // altstack: abs(a), is_positive

                for _ in 0..3 {
                    OP_SIZE 3 OP_LESSTHAN OP_IF OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT OP_ENDIF
                }

                OP_FROMALTSTACK
                OP_IF
                    OP_PUSHBYTES_1 OP_PUSHBYTES_0
                OP_ELSE
                    OP_PUSHBYTES_1 OP_LEFT
                OP_ENDIF
                OP_CAT
            OP_ELSE
                OP_DROP
            OP_ENDIF
        }
    }

    fn reduce() -> Script {
        script! {
            OP_DUP OP_NOT OP_NOTIF OP_1SUB OP_ENDIF
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
            { Self::reduce() }
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
            OP_FROMALTSTACK
            { Self::reduce() }
            OP_FROMALTSTACK
            { Self::reduce() }
            OP_SWAP
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
            OP_FROMALTSTACK
            { Self::reduce() }
            OP_FROMALTSTACK
            { Self::reduce() }
            OP_FROMALTSTACK
            { Self::reduce() }
            OP_FROMALTSTACK
            { Self::reduce() }
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
            OP_FROMALTSTACK
            { Self::reduce() }
            OP_FROMALTSTACK
            { Self::reduce() }
            OP_FROMALTSTACK
            { Self::reduce() }
            OP_FROMALTSTACK
            { Self::reduce() }
            OP_FROMALTSTACK
            { Self::reduce() }
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

        let mut hash = [0u8; 32];
        hash[0] = 0xff;
        hash[1] = 0xff;
        hash[2] = 0xff;
        hash[3] = 0x7f;

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
        hash[0] = 0x02;
        hash[1] = 0x00;
        hash[2] = 0x00;
        hash[3] = 0x80;

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
