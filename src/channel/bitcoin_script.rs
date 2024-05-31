use crate::channel::{Extraction5M31, ExtractionQM31};
use crate::treepp::*;
use crate::utils::trim_m31_gadget;

/// Gadget for a channel.
pub struct ChannelGadget;

impl ChannelGadget {
    /// Initialize a channel.
    pub fn create_channel(hash: [u8; 32]) -> Script {
        script! {
            { hash.to_vec() }
        }
    }

    /// Absorb a commitment.
    pub fn absorb_commitment() -> Script {
        script! {
            OP_CAT OP_SHA256
        }
    }

    /// Absorb a qm31 element.
    pub fn absorb_qm31() -> Script {
        script! {
            OP_TOALTSTACK
            { CommitmentGadget::commit_qm31() }
            OP_FROMALTSTACK OP_CAT OP_SHA256
        }
    }

    /// Squeeze a qm31 element using hints.
    pub fn squeeze_qm31_using_hint() -> Script {
        script! {
            OP_DUP OP_SHA256 OP_SWAP
            OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT OP_SHA256
            { ExtractorGadget::unpack_qm31() }
        }
    }

    /// Squeeze five queries from the channel, each of logn bits, using hints.
    pub fn squeeze_5queries_using_hint(logn: usize) -> Script {
        script! {
            OP_DUP OP_SHA256 OP_SWAP
            OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT OP_SHA256
            { ExtractorGadget::unpack_5m31() }
            { trim_m31_gadget(logn) } OP_TOALTSTACK
            { trim_m31_gadget(logn) } OP_TOALTSTACK
            { trim_m31_gadget(logn) } OP_TOALTSTACK
            { trim_m31_gadget(logn) } OP_TOALTSTACK
            { trim_m31_gadget(logn) }
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
        }
    }
}

/// Gadget for committing field elements.
pub struct CommitmentGadget;

impl CommitmentGadget {
    /// Commit a qm31 element.
    pub fn commit_qm31() -> Script {
        script! {
            OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256
        }
    }
}

/// Gadget for extracting elements.
pub struct ExtractorGadget;
impl ExtractorGadget {
    /// Push the hint for extracting a qm31 element from a hash.
    pub fn push_hint_qm31(e: &ExtractionQM31) -> Script {
        script! {
            { e.0.0 }
            { e.0.1 }
            { e.0.2 }
            { e.0.3 }
            { e.1.to_vec() }
        }
    }

    /// Push the hint for extracting five m31 elements from a hash.
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

    /// Reconstruct a 4-byte representation from a Bitcoin integer.
    ///
    /// Idea: extract the positive/negative symbol and pad it accordingly.
    fn reconstruct() -> Script {
        script! {
            // handle 0x80 specially---it is the "negative zero", but most arithmetic opcodes refuse to work with it.
            OP_DUP OP_PUSHBYTES_1 OP_LEFT OP_EQUAL
            OP_IF
                OP_DROP
                OP_PUSHBYTES_0 OP_TOALTSTACK
                OP_PUSHBYTES_4 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_LEFT
            OP_ELSE
                OP_DUP OP_ABS
                OP_DUP OP_TOALTSTACK

                OP_SIZE 4 OP_LESSTHAN
                OP_IF
                    OP_DUP OP_ROT
                    OP_EQUAL OP_TOALTSTACK

                    // stack: abs(a)
                    // altstack: abs(a), is_positive

                    OP_SIZE 2 OP_LESSTHAN OP_IF OP_PUSHBYTES_2 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_CAT OP_ENDIF
                    OP_SIZE 3 OP_LESSTHAN OP_IF OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT OP_ENDIF

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
            OP_ENDIF
        }
    }

    /// Reduce the number from [0, 2^31-1] to [0, 2^31-2] by subtracting 1 from any element that is not zero.
    /// This is because 2^31-1 is the modulus and a reduced element should be smaller than it.
    /// The sampling, therefore, has a small bias.
    fn reduce() -> Script {
        script! {
            OP_DUP OP_NOT OP_NOTIF OP_1SUB OP_ENDIF
        }
    }

    /// Unpack the hash into a qm31 element.
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
        }
    }

    /// Unpack the hash into five m31 elements.
    /// TODO: This function needs to be generalized for other number of elements.
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
    use crate::channel::{Channel, ChannelGadget, Commitment, CommitmentGadget, ExtractorGadget};
    use crate::tests_utils::report::report_bitcoin_script_size;
    use crate::treepp::*;
    use bitcoin_script::script;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::fields::cm31::CM31;
    use stwo_prover::core::fields::m31::M31;
    use stwo_prover::core::fields::qm31::QM31;

    #[test]
    fn test_absorb_commitment() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let channel_script = ChannelGadget::absorb_commitment();
        report_bitcoin_script_size("Channel", "absorb_commitment", channel_script.len());

        let mut init_state = [0u8; 32];
        init_state.iter_mut().for_each(|v| *v = prng.gen());

        let mut elem = [0u8; 32];
        elem.iter_mut().for_each(|v| *v = prng.gen());

        let mut channel = Channel::new(init_state);
        channel.absorb_commitment(&Commitment(elem));

        let final_state = channel.state;

        let script = script! {
            { elem.to_vec() }
            { init_state.to_vec() }
            { channel_script.clone() }
            { final_state.to_vec() }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_absorb_qm31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let channel_script = ChannelGadget::absorb_qm31();
        report_bitcoin_script_size("Channel", "absorb_qm31", channel_script.len());

        let mut init_state = [0u8; 32];
        init_state.iter_mut().for_each(|v| *v = prng.gen());

        let elem = QM31(
            CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
            CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
        );

        let mut channel = Channel::new(init_state);
        channel.absorb_qm31(&elem);

        let final_state = channel.state;

        let script = script! {
            { elem }
            { init_state.to_vec() }
            { channel_script.clone() }
            { final_state.to_vec() }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_squeeze_qm31_using_hint() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let channel_script = ChannelGadget::squeeze_qm31_using_hint();
        report_bitcoin_script_size("Channel", "squeeze_qm31_using_hint", channel_script.len());

        for _ in 0..100 {
            let mut a = [0u8; 32];
            a.iter_mut().for_each(|v| *v = prng.gen());

            let mut channel = Channel::new(a);
            let (b, hint) = channel.draw_qm31();

            let c = channel.state;

            let script = script! {
                { ExtractorGadget::push_hint_qm31(&hint) }
                { a.to_vec() }
                { channel_script.clone() }
                { b }
                qm31_equalverify
                { c.to_vec() }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_squeeze_5queries_using_hint() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let channel_script = ChannelGadget::squeeze_5queries_using_hint(15);

        report_bitcoin_script_size(
            "Channel",
            "squeeze_5queries_using_hint",
            channel_script.len(),
        );

        for _ in 0..100 {
            let mut a = [0u8; 32];
            a.iter_mut().for_each(|v| *v = prng.gen());

            let mut channel = Channel::new(a);
            let (b, hint) = channel.draw_5queries(15);

            let c = channel.state;

            let script = script! {
                { ExtractorGadget::push_hint_5m31(&hint) }
                { a.to_vec() }
                { channel_script.clone() }
                { b[4] } OP_EQUALVERIFY
                { b[3] } OP_EQUALVERIFY
                { b[2] } OP_EQUALVERIFY
                { b[1] } OP_EQUALVERIFY
                { b[0] } OP_EQUALVERIFY
                { c.to_vec() }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_commit_qm31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let commit_script = CommitmentGadget::commit_qm31();

        report_bitcoin_script_size("QM31", "commit", commit_script.len());

        for _ in 0..100 {
            let a = QM31(
                CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
            );
            let b = Commitment::commit_qm31(a);

            let script = script! {
                { a }
                { commit_script.clone() }
                { b.clone() }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        // make sure OP_CAT is not OP_SUCCESS
        let script = script! {
            OP_CAT
            OP_RETURN
        };
        let exec_result = execute_script(script);
        assert!(!exec_result.success);
    }
}
