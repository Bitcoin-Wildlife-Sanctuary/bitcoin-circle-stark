use crate::pow::hash_with_nonce;
use crate::treepp::*;

/// Gadget for verifying PoW.
pub struct PowGadget;

impl PowGadget {
    /// Verify the PoW in Bitcoin script.
    /// input:
    ///  channel (32 bytes)
    ///  nonce (64-bit string, aka 8 bytes)
    ///  suffix (the sha256 result after the leading zero bytes and the MSB [if applicable])
    ///  msb (applicable if n_bits % 8 != 0)
    ///
    /// output:
    ///  channel' = sha256(channel || nonce)
    ///
    /// require:
    ///  {0x00}^(n_bits // 8) || msb || suffix != sha256(channel||nonce)
    ///     where msb is required if n_bits % 8 != 0 and should not be present if it is not
    ///  msb starts with n_bits % 8 (which would be at least 1) zero bits.
    pub fn verify_pow(n_bits: usize) -> Script {
        assert!(n_bits > 0);

        script! {
            // move the msb away for simplicity
            if n_bits % 8 != 0 {
                OP_TOALTSTACK
            }

            // check the length of the nonce
            1 OP_PICK
            OP_SIZE 8 OP_EQUALVERIFY
            OP_DROP

            // check the length of the suffix
            OP_SIZE { 32 - ((n_bits  + 7) / 8) } OP_EQUALVERIFY

            // compute the channel and nonce
            OP_ROT OP_ROT
            OP_CAT
            OP_SHA256
            OP_SWAP

            // current stack:
            //   new channel
            //   suffix
            //
            // altstack:
            //   msb (if applicable)

            // push the necessary number of zeroes
            if n_bits / 8 > 0 {
                { vec![0u8; n_bits / 8] }
            }

            // if msb is present, check the msb is small enough,
            // and if it is a zero, make it `0x00`
            if n_bits % 8 != 0 {
                OP_FROMALTSTACK
                OP_DUP
                0 OP_GREATERTHANOREQUAL OP_VERIFY
                OP_DUP
                { 1 << (8 - n_bits % 8)  } OP_LESSTHAN OP_VERIFY
                OP_DUP
                0 OP_EQUAL OP_IF
                    OP_DROP OP_PUSHBYTES_1 OP_PUSHBYTES_0
                OP_ENDIF

                if n_bits / 8 > 0 {
                    OP_CAT
                }
            }

            // current stack:
            //   new channel
            //   suffix
            //   prefix

            OP_SWAP
            OP_CAT

            OP_OVER
            OP_EQUALVERIFY
        }
    }

    /// Push the hint for verifying the PoW.
    /// It contains the nonce, the suffix, and the msb (if n_bits % 8 != 0).
    ///
    /// Need to be copied to the right location. `verify_pow` does not use the hint stack.
    pub fn push_pow_hint(channel_digest: Vec<u8>, nonce: u64, n_bits: usize) -> Script {
        assert!(n_bits > 0);

        let digest = hash_with_nonce(&channel_digest, nonce);

        script! {
            { nonce.to_le_bytes().to_vec() }
            if n_bits % 8 == 0 {
                { digest[(n_bits / 8)..].to_vec() }
            } else {
                { digest[(n_bits + 8 - 1) / 8..].to_vec() }
                { digest[n_bits / 8] }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{tests_utils::report::report_bitcoin_script_size, treepp::*};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::pow::{bitcoin_script::PowGadget, grind_find_nonce, hash_with_nonce};

    #[test]
    fn test_push_pow_hint() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut channel_digest = vec![0u8; 32];
        prng.fill_bytes(&mut channel_digest);

        let nonce = grind_find_nonce(channel_digest.clone(), 1);
        let new_channel = hash_with_nonce(&channel_digest, nonce);

        let script = script! {
            { PowGadget::push_pow_hint(channel_digest.clone(), nonce, 1) }
            { new_channel[0] }
            OP_EQUALVERIFY
            { new_channel[1..].to_vec() }
            OP_EQUALVERIFY
            { nonce.to_le_bytes().to_vec() }
            OP_EQUALVERIFY
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_fail_verify() {
        let n_bits = 8;

        let mut prng = ChaCha20Rng::seed_from_u64(1337);

        let mut channel_digest = [0u8; 32].to_vec();
        prng.fill_bytes(&mut channel_digest);

        let nonce = 1337;

        let script = script! {
            { channel_digest.clone() }
            { PowGadget::push_pow_hint(channel_digest.clone(), nonce, n_bits) }
            { PowGadget::verify_pow(n_bits)}
            OP_DROP
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(!exec_result.success);

        let n_bits = 1;

        let mut prng = ChaCha20Rng::seed_from_u64(1337);

        let mut channel_digest = [0u8; 32].to_vec();
        prng.fill_bytes(&mut channel_digest);

        let nonce = 1337 + 4;

        let script = script! {
            { channel_digest.clone() }
            { PowGadget::push_pow_hint(channel_digest.clone(), nonce, n_bits) }
            { PowGadget::verify_pow(n_bits)}
            OP_DROP
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(!exec_result.success);

        let n_bits = 12;

        let mut prng = ChaCha20Rng::seed_from_u64(1337);

        let mut channel_digest = [0u8; 32].to_vec();
        prng.fill_bytes(&mut channel_digest);

        let nonce = 1337;

        let script = script! {
            { channel_digest.clone() }
            { PowGadget::push_pow_hint(channel_digest.clone(), nonce, n_bits) }
            { PowGadget::verify_pow(n_bits)}
            OP_DROP
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(!exec_result.success);
    }

    #[test]
    fn test_pow() {
        for prng_seed in 0..5 {
            for n_bits in 1..=20 {
                let mut prng = ChaCha20Rng::seed_from_u64(prng_seed);

                let mut channel_digest = [0u8; 32].to_vec();
                prng.fill_bytes(&mut channel_digest);

                let nonce = grind_find_nonce(channel_digest.clone(), n_bits.try_into().unwrap());

                let verify_pow_script = PowGadget::verify_pow(n_bits);
                if prng_seed == 0 {
                    report_bitcoin_script_size(
                        "POW",
                        format!("verify_pow({} bits)", n_bits).as_str(),
                        verify_pow_script.len(),
                    );
                }

                let script = script! {
                    { channel_digest.clone() }
                    { PowGadget::push_pow_hint(channel_digest.clone(), nonce, n_bits) }
                    { verify_pow_script.clone() }
                    { channel_digest.clone() }
                    { nonce.to_le_bytes().to_vec() }
                    OP_CAT
                    OP_SHA256
                    OP_EQUALVERIFY // checking that indeed channel' = sha256(channel||nonce)
                    OP_TRUE
                };
                let exec_result = execute_script(script);
                assert!(exec_result.success);
            }
        }

        report_bitcoin_script_size(
            "POW",
            "verify_pow(78 bits)",
            PowGadget::verify_pow(78).len(),
        );
    }
}
