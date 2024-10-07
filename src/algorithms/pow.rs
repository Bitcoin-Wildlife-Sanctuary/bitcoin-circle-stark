use crate::channel::Sha256ChannelGadget;
use crate::pow::PoWHint;
use crate::treepp::*;
use anyhow::Error;
use bitcoin_script_dsl::builtins::hash::HashVar;
use bitcoin_script_dsl::builtins::str::StrVar;
use bitcoin_script_dsl::bvar::{AllocVar, BVar};
use bitcoin_script_dsl::options::Options;
use bitcoin_script_dsl::stack::Stack;
use stwo_prover::core::channel::{Channel, Sha256Channel};
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

pub fn verify_pow(hash: &mut HashVar, n_bits: u32, nonce: u64) -> anyhow::Result<()> {
    let old_channel_digest = hash.value.to_vec();
    let pow_hint = PoWHint::new(
        Sha256Hash::from(old_channel_digest.as_slice()),
        nonce,
        n_bits,
    );

    let mut channel = Sha256Channel::default();
    channel.update_digest(Sha256Hash::from(old_channel_digest));
    channel.mix_nonce(nonce);
    if channel.trailing_zeros() < n_bits {
        return Err(Error::msg("The proof of work requirement is not satisfied"));
    }

    let cs = hash.cs();

    let nonce_var = StrVar::new_hint(&cs, pow_hint.nonce.to_le_bytes().to_vec())?;
    let prefix_var = StrVar::new_hint(&cs, pow_hint.prefix)?;
    let msb_var = StrVar::new_hint(&cs, vec![pow_hint.msb.unwrap_or_default()])?;
    // if msb is not required, still push a stack element to make sure that the max stack consumption
    // is data-independent

    cs.insert_script_complex(
        verify_pow_gadget,
        hash.variables()
            .iter()
            .chain(nonce_var.variables().iter())
            .chain(prefix_var.variables().iter())
            .chain(msb_var.variables().iter())
            .copied(),
        &Options::new().with_u32("n_bits", n_bits),
    )?;

    *hash = HashVar::new_function_output(&cs, channel.digest().as_ref().to_vec())?;

    Ok(())
}

fn verify_pow_gadget(_: &mut Stack, options: &Options) -> anyhow::Result<Script> {
    let n_bits = options.get_u32("n_bits")?;
    assert!(n_bits > 0);
    let n_bits = n_bits as usize;

    // NOTE: nonce should not be assumed to be a constant in the script.
    Ok(script! {
        // Stack:
        // - channel
        // - nonce
        // - prefix
        // - msb

        // pull the nonce
        2 OP_ROLL

        // check the length of the nonce
        OP_SIZE 8 OP_EQUALVERIFY

        // mix the nonce
        3 OP_ROLL
        { Sha256ChannelGadget::mix_nonce() }

        // stack:
        // - prefix
        // - msb
        // - new_channel

        // pull the prefix
        2 OP_ROLL

        // check the length of the prefix
        OP_SIZE { 32 - ((n_bits  + 7) / 8) } OP_EQUALVERIFY

        // if msb is present, check the msb is small enough,
        // and if it is a zero, make it `0x00`
        if n_bits % 8 != 0 {
            2 OP_ROLL
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

        if n_bits % 8 == 0 {
            OP_SWAP OP_DROP
        }
        // drop the dummy msb element if it is not needed
    })
}
