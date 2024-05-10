use crate::channel::{Channel, ChannelGadget};
use crate::channel_extract::{ExtractionQM31, ExtractorGadget};
use crate::fri::FriProof;
use bitvm::treepp::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rust_bitcoin_u31_or_u30::{u31ext_fromaltstack, u31ext_toaltstack, QM31 as QM31Gadget};

pub struct FRIGadget;

impl FRIGadget {
    pub fn push_fiat_shamir_input(channel: &mut Channel, logn: usize, proof: &FriProof) -> Script {
        let mut factors_hints = Vec::<ExtractionQM31>::new();
        let n_layers = proof.commitments.len();

        for c in proof.commitments.iter() {
            channel.absorb_commitment(c);
            let res = channel.draw_element();
            factors_hints.push(res.1);
        }
        proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));

        let res = channel.draw_5queries(logn);
        let queries_hint = res.1;

        script! {
            for hint in factors_hints.iter() {
                { ExtractorGadget::push_hint_qm31(hint) }
            }
            { ExtractorGadget::push_hint_5m31(&queries_hint) }

            for elem in proof.last_layer.iter().rev() {
                { *elem }
            }
            for c in proof.commitments.iter().rev() {
                { c.clone() }
            }
        }
    }

    pub fn check_fiat_shamir(logn: usize, n_layers: usize, n_last_layer: usize) -> Script {
        let channel_init_state = {
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let mut channel_init_state = [0u8; 32];
            channel_init_state.iter_mut().for_each(|v| *v = prng.gen());
            channel_init_state
        };

        script! {
            { channel_init_state.to_vec() }

            for _ in 0..n_layers {
                { ChannelGadget::absorb_commitment() }
                { ChannelGadget::squeeze_element_using_hint() }
                { u31ext_toaltstack::<QM31Gadget>() }
            }

            for _ in 0..n_last_layer {
                { ChannelGadget::absorb_qm31() }
            }

            { ChannelGadget::squeeze_5queries_using_hint(logn) }

            // remove the channel
            5 OP_ROLL OP_DROP

            for _ in 0..n_layers {
                { u31ext_fromaltstack::<QM31Gadget>() }
            }
        }
    }
}
