use crate::channel::Sha256ChannelGadget;
use crate::treepp::*;
use crate::OP_HINT;

/// Gadget for verifying PoW.
pub struct PowGadget;

impl PowGadget {
    /// Verify the PoW in Bitcoin script.
    ///
    /// Hint:
    /// - nonce (64-bit string, aka 8 bytes)
    /// - prefix (the sha256 result after the leading zero bytes and the MSB [if applicable])
    /// - msb (applicable if n_bits % 8 != 0)
    ///
    /// Input:
    ///  channel digest
    ///
    /// Output:
    ///  new channel digest = channel.mix_nonce(nonce)
    ///
    /// require:
    ///  prefix || msb || {0x00}^(n_bits // 8)  != sha256(channel||nonce)
    ///     where msb is required if n_bits % 8 != 0 and should not be present if it is not
    ///  msb starts with n_bits % 8 (which would be at least 1) zero bits.
    pub fn verify_pow(n_bits: u32) -> Script {
        assert!(n_bits > 0);
        let n_bits = n_bits as usize;

        script! {
            // pull the nonce
            OP_HINT

            // check the length of the nonce
            OP_SIZE 8 OP_EQUALVERIFY

            OP_SWAP
            { Sha256ChannelGadget::mix_nonce() }
            // stack: new_channel

            // pull the prefix
            OP_HINT

            // check the length of the prefix
            OP_SIZE { 32 - ((n_bits  + 7) / 8) } OP_EQUALVERIFY

            // if msb is present, check the msb is small enough,
            // and if it is a zero, make it `0x00`
            if n_bits % 8 != 0 {
                OP_HINT
                OP_DUP
                0 OP_GREATERTHANOREQUAL OP_VERIFY
                OP_DUP
                { 1 << (8 - n_bits % 8)  } OP_LESSTHAN OP_VERIFY
                OP_DUP
                0 OP_EQUAL OP_IF
                    OP_DROP OP_PUSHBYTES_1 OP_PUSHBYTES_0
                OP_ENDIF

                OP_CAT
            }

            // push the necessary number of zeroes
            if n_bits / 8 > 0 {
                { vec![0u8; n_bits / 8] }
                OP_CAT
            }

            OP_OVER
            OP_EQUALVERIFY
        }
    }
}

#[cfg(test)]
mod test {
    use crate::channel::Sha256Channel;
    use crate::{tests_utils::report::report_bitcoin_script_size, treepp::*};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_prover::core::channel::Channel;
    use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

    use crate::pow::{bitcoin_script::PowGadget, PoWHint};

    // A handy function for grinding, which finds a nonce that makes the resulting hash with enough zeroes.
    fn grind_find_nonce(channel_digest: Vec<u8>, n_bits: u32) -> u64 {
        let mut nonce = 0u64;

        let mut channel = Sha256Channel::default();
        channel.update_digest(channel_digest.into());

        loop {
            let mut channel = channel.clone();
            channel.mix_nonce(nonce);
            if channel.trailing_zeros() >= n_bits {
                return nonce;
            }
            nonce += 1;
        }
    }

    #[test]
    fn test_push_pow_hint() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut channel_digest = vec![0u8; 32];
        prng.fill_bytes(&mut channel_digest);

        let nonce = grind_find_nonce(channel_digest.clone(), 1);

        let mut channel = Sha256Channel::default();
        channel.update_digest(channel_digest.clone().into());
        channel.mix_nonce(nonce);

        let new_channel_digest = channel.digest();
        let new_channel = new_channel_digest.as_ref();

        let pow_hint = PoWHint::new(Sha256Hash::from(channel_digest), nonce, 1);

        let script = script! {
            { pow_hint }
            { new_channel[31] }
            OP_EQUALVERIFY
            { new_channel[..31].to_vec() }
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

        let pow_hint = PoWHint::new(Sha256Hash::from(channel_digest.as_slice()), nonce, n_bits);

        let script = script! {
            { pow_hint }
            { channel_digest.clone() }
            { PowGadget::verify_pow(n_bits) }
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

        let pow_hint = PoWHint::new(Sha256Hash::from(channel_digest.as_slice()), nonce, n_bits);

        let script = script! {
            { pow_hint }
            { channel_digest.clone() }
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

        let pow_hint = PoWHint::new(Sha256Hash::from(channel_digest.as_slice()), nonce, n_bits);

        let script = script! {
            { pow_hint }
            { channel_digest.clone() }
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

                let nonce = grind_find_nonce(channel_digest.clone(), n_bits);

                let verify_pow_script = PowGadget::verify_pow(n_bits);
                if prng_seed == 0 {
                    report_bitcoin_script_size(
                        "POW",
                        format!("verify_pow ({} bits)", n_bits).as_str(),
                        verify_pow_script.len(),
                    );
                }

                let pow_hint =
                    PoWHint::new(Sha256Hash::from(channel_digest.clone()), nonce, n_bits);

                let mut channel = Sha256Channel::default();
                channel.update_digest(channel_digest.clone().into());
                channel.mix_nonce(nonce);

                let script = script! {
                    { pow_hint }
                    { channel_digest.clone() }
                    { verify_pow_script.clone() }
                    { channel.digest }
                    OP_EQUAL
                };
                let exec_result = execute_script(script);
                assert!(exec_result.success);
            }
        }

        report_bitcoin_script_size(
            "POW",
            "verify_pow (78 bits)",
            PowGadget::verify_pow(78).len(),
        );
    }
}
