use crate::treepp::*;
use crate::utils::{hash, hash_qm31_gadget, trim_m31_gadget};
use crate::OP_HINT;
use rust_bitcoin_m31::MOD;

/// Gadget for a channel.
pub struct Sha256ChannelGadget;

impl Sha256ChannelGadget {
    /// Absorb a commitment.
    ///
    /// Input:
    /// - digest
    /// - old channel digest
    ///
    /// Output:
    /// - new channel digest
    pub fn mix_digest() -> Script {
        script! {
            OP_CAT hash
        }
    }

    /// Absorb a qm31 element.
    ///
    /// Input:
    /// - qm31
    /// - old channel digest
    ///
    /// Output:
    /// - new channel digest
    pub fn mix_felt() -> Script {
        script! {
            OP_TOALTSTACK
            hash_qm31_gadget
            OP_FROMALTSTACK OP_CAT hash
        }
    }

    /// Absorb a nonce.
    ///
    /// Input:
    /// - nonce (8 bytes)
    /// - old channel digest
    ///
    /// Output:
    /// - new channel digest
    pub fn mix_nonce() -> Script {
        script! {
            OP_SWAP
            OP_SIZE 8 OP_EQUALVERIFY

            OP_PUSHBYTES_3 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0
            OP_DUP OP_CAT
            OP_DUP OP_CAT
            OP_DUP OP_CAT
            OP_CAT OP_SWAP
            { Self::mix_digest() }
        }
    }

    /// Draw a qm31 element using hints.
    ///
    /// Input:
    /// - old channel digest
    ///
    /// Output:
    /// - new channel digest
    /// - qm31
    pub fn draw_felt_with_hint() -> Script {
        script! {
            OP_DUP hash OP_SWAP
            OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT hash
            { Self::unpack_multi_m31(4) }
        }
    }

    /// Draw queries from the channel, each of logn bits, using hints.
    ///
    /// Output:
    ///    all the numbers (m)
    ///    channel digest
    pub fn draw_numbers_with_hint(m: usize, logn: usize) -> Script {
        script! {
            for _ in 0..(m / 8) {
                OP_DUP hash OP_SWAP
                OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT hash
                { Self::unpack_multi_m31(8) }
                for i in 0..8 {
                    { i } OP_ROLL { trim_m31_gadget(logn) }
                }
                8 OP_ROLL
            }
            if m % 8 != 0 {
                OP_DUP hash OP_SWAP
                OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT hash
                { Self::unpack_multi_m31(m % 8) }
                for i in 0..m % 8 {
                    { i } OP_ROLL { trim_m31_gadget(logn) }
                }
                { m % 8 } OP_ROLL
            }
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

    /// Unpack multiple m31 and put them on the stack.
    pub fn unpack_multi_m31(m: usize) -> Script {
        script! {
            for _ in 0..m {
                OP_HINT
            }

            for _ in 0..m {
                { m - 1 } OP_ROLL
                { Self::reconstruct() }
            }

            for _ in 0..m-1 {
                OP_CAT
            }

            if m % 8 != 0 {
                OP_HINT OP_CAT
            }

            OP_EQUALVERIFY

            for _ in 0..m {
                OP_FROMALTSTACK

                OP_DUP { MOD } OP_EQUAL OP_IF
                    OP_NOT
                OP_ENDIF
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::channel::{generate_hints, ChannelWithHint, Sha256Channel, Sha256ChannelGadget};
    use crate::tests_utils::report::report_bitcoin_script_size;
    use crate::treepp::*;
    use crate::utils::{get_rand_qm31, hash, hash_qm31, hash_qm31_gadget};
    use bitcoin_script::script;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::channel::Channel;
    use stwo_prover::core::vcs::sha256_hash::{Sha256Hash, Sha256Hasher};

    #[test]
    fn test_mix_digest() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let channel_script = Sha256ChannelGadget::mix_digest();
        report_bitcoin_script_size("Channel", "mix_digest", channel_script.len());

        let mut init_state = [0u8; 32];
        init_state.iter_mut().for_each(|v| *v = prng.gen());
        let init_state = Sha256Hash::from(init_state.to_vec());

        let mut elem = [0u8; 32];
        elem.iter_mut().for_each(|v| *v = prng.gen());
        let elem = Sha256Hash::from(elem.to_vec());

        let mut channel = Sha256Channel::default();
        channel.update_digest(init_state);
        channel.update_digest(Sha256Hasher::concat_and_hash(&elem, &channel.digest()));

        let final_state = channel.digest;

        let script = script! {
            { elem }
            { init_state }
            { channel_script.clone() }
            { final_state }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_mix_felt() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let channel_script = Sha256ChannelGadget::mix_felt();
        report_bitcoin_script_size("Channel", "mix_felt", channel_script.len());

        let mut init_state = [0u8; 32];
        init_state.iter_mut().for_each(|v| *v = prng.gen());
        let init_state = Sha256Hash::from(init_state.to_vec());

        let elem = get_rand_qm31(&mut prng);

        let mut channel = Sha256Channel::default();
        channel.update_digest(init_state);
        channel.mix_felts(&[elem]);

        let final_state = channel.digest;

        let script = script! {
            { elem }
            { init_state }
            { channel_script.clone() }
            { final_state }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_mix_nonce() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let channel_script = Sha256ChannelGadget::mix_nonce();
        report_bitcoin_script_size("Channel", "mix_nonce", channel_script.len());

        let mut init_state = [0u8; 32];
        init_state.iter_mut().for_each(|v| *v = prng.gen());
        let init_state = Sha256Hash::from(init_state.to_vec());

        let nonce = prng.gen::<u64>();

        let mut channel = Sha256Channel::default();
        channel.update_digest(init_state);
        channel.mix_nonce(nonce);

        let final_state = channel.digest;

        let script = script! {
            { nonce.to_le_bytes().to_vec() }
            { init_state }
            { channel_script.clone() }
            { final_state }
            OP_EQUAL
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_draw_8_elements() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let mut a = [0u8; 32];
            a.iter_mut().for_each(|v| *v = prng.gen());
            let a = Sha256Hash::from(a.to_vec());

            let mut channel = Sha256Channel::default();
            channel.update_digest(a);
            let (b, hint) = channel.draw_m31_and_hints(8);

            let c = channel.digest;

            let script = script! {
                { hint }
                { a }
                OP_DUP hash OP_SWAP
                OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT hash
                { Sha256ChannelGadget::unpack_multi_m31(8) }
                for i in 0..8 {
                    { b[i] }
                    OP_EQUALVERIFY
                }
                { c }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_draw_felt_with_hint() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let channel_script = Sha256ChannelGadget::draw_felt_with_hint();
        report_bitcoin_script_size("Channel", "draw_felt_with_hint", channel_script.len());

        for _ in 0..100 {
            let mut a = [0u8; 32];
            a.iter_mut().for_each(|v| *v = prng.gen());
            let a = Sha256Hash::from(a.to_vec());

            let mut channel = Sha256Channel::default();
            channel.update_digest(a);
            let (b, hint) = channel.draw_felt_and_hints();

            let c = channel.digest;

            let script = script! {
                { hint }
                { a }
                { channel_script.clone() }
                { b }
                qm31_equalverify
                { c }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_draw_many_numbers_with_hint() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let channel_script = Sha256ChannelGadget::draw_numbers_with_hint(8, 10);
        report_bitcoin_script_size("Channel", "draw_8numbers_with_hint", channel_script.len());

        for _ in 0..10 {
            let mut a = [0u8; 32];
            a.iter_mut().for_each(|v| *v = prng.gen());
            let a = Sha256Hash::from(a.to_vec());

            let mut channel = Sha256Channel::default();
            channel.update_digest(a);
            let (b, hint) = channel.draw_queries_and_hints(8, 10);

            let c = channel.digest;

            let script = script! {
                { hint }
                { a }
                { channel_script.clone() }
                OP_TOALTSTACK
                for i in 0..8 {
                    { b[7 - i] }
                    OP_EQUALVERIFY
                }
                OP_FROMALTSTACK
                { c }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        let channel_script = Sha256ChannelGadget::draw_numbers_with_hint(12, 10);
        report_bitcoin_script_size("Channel", "draw_12numbers_with_hint", channel_script.len());

        for _ in 0..10 {
            let mut a = [0u8; 32];
            a.iter_mut().for_each(|v| *v = prng.gen());
            let a = Sha256Hash::from(a.to_vec());

            let mut channel = Sha256Channel::default();
            channel.update_digest(a);
            let (b, hint) = channel.draw_queries_and_hints(12, 10);

            let c = channel.digest;

            let script = script! {
                { hint }
                { a }
                { channel_script.clone() }
                OP_TOALTSTACK
                for i in 0..12 {
                    { b[11 - i] }
                    OP_EQUALVERIFY
                }
                OP_FROMALTSTACK
                { c }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_hash_felt() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let commit_script = hash_qm31_gadget();
        report_bitcoin_script_size("QM31", "hash", commit_script.len());

        for _ in 0..100 {
            let a = get_rand_qm31(&mut prng);
            let b = hash_qm31(&a);

            let script = script! {
                { a }
                { commit_script.clone() }
                { b.to_vec() }
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

    #[test]
    fn test_corner_case() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut h = [0u8; 32];
        h[3] = 0x80;
        for elem in h.iter_mut().skip(4) {
            *elem = prng.gen();
        }

        let (_, hint) = generate_hints(1, &h);

        let script = script! {
            { hint }
            { Sha256ChannelGadget::unpack_multi_m31(1) }
            OP_NOT
        };
        let exec_result = execute_script(script);
        assert!(!exec_result.success);
    }
}
