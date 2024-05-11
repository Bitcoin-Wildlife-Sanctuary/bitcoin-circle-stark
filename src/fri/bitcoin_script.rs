use crate::channel::{Channel, ChannelGadget};
use crate::channel_extract::{ExtractionQM31, ExtractorGadget};
use crate::fri::{FriProof, N_QUERIES};
use crate::twiddle_merkle_tree::TwiddleMerkleTreeGadget;
use bitvm::treepp::*;
use rust_bitcoin_u31_or_u30::{u31ext_fromaltstack, u31ext_toaltstack, QM31 as QM31Gadget};

pub struct FRIGadget;

impl FRIGadget {
    pub fn push_fiat_shamir_input(channel: &mut Channel, logn: usize, proof: &FriProof) -> Script {
        let mut factors_hints = Vec::<ExtractionQM31>::new();

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

    pub fn check_fiat_shamir(
        channel_init_state: &[u8; 32],
        logn: usize,
        n_layers: usize,
    ) -> Script {
        let n_last_layer = 1 << (logn - n_layers);
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

    pub fn push_twiddle_merkle_tree_proof(fri_proof: &FriProof) -> Script {
        script! {
            for proof in fri_proof.twiddle_merkle_proofs.iter() {
                for elem in proof.leaf.iter() {
                    { *elem }
                }
                for elem in proof.siblings.iter() {
                    { elem.to_vec() }
                }
            }
        }
    }

    pub fn check_twiddle_merkle_tree_proof(
        logn: usize,
        twiddle_merkle_tree_root: [u8; 32],
    ) -> Script {
        // input: twiddle proof * 5, pos * 5
        // output: leaves * 5

        script! {
            for _ in 0..N_QUERIES {
                OP_TOALTSTACK
            }

            for _ in 0..N_QUERIES {
                { twiddle_merkle_tree_root.to_vec() }
                OP_FROMALTSTACK
                { TwiddleMerkleTreeGadget::query_and_verify(logn - 1) }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::channel::Channel;
    use crate::circle::CirclePoint;
    use crate::fri;
    use crate::fri::FRIGadget;
    use crate::math::Field;
    use crate::twiddle_merkle_tree::{TwiddleMerkleTree, TWIDDLE_MERKLE_TREE_ROOT_4};
    use crate::utils::permute_eval;
    use bitvm::treepp::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_u31_or_u30::u31ext_equalverify;
    use rust_bitcoin_u31_or_u30::QM31 as QM31Gadget;

    #[test]
    fn test_fiat_shamir() {
        let channel_init_state = {
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let mut channel_init_state = [0u8; 32];
            channel_init_state.iter_mut().for_each(|v| *v = prng.gen());
            channel_init_state
        };

        let mut channel = Channel::new(channel_init_state.clone());
        let logn = 5;

        let proof = {
            let p = CirclePoint::subgroup_gen(logn + 1);

            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let mut channel_init_state = [0u8; 32];
            channel_init_state.iter_mut().for_each(|v| *v = prng.gen());

            let evaluation = (0..(1 << logn))
                .map(|i| (p.mul(i * 2 + 1).x.square().square() + 1.into()).into())
                .collect();
            let evaluation = permute_eval(evaluation);

            let proof = fri::fri_prove(&mut Channel::new(channel_init_state), evaluation);
            proof
        };

        let expected = {
            let mut channel = Channel::new(channel_init_state);
            let mut expected_1 = vec![];

            for c in proof.commitments.iter() {
                channel.absorb_commitment(c);
                let res = channel.draw_element();
                expected_1.push(res.0);
            }
            proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));

            let res = channel.draw_5queries(logn);

            let expected_2 = res.0;

            (expected_1, expected_2)
        };

        let script = script! {
            { FRIGadget::push_fiat_shamir_input(&mut channel, logn, &proof) }
            { FRIGadget::check_fiat_shamir(&channel_init_state, logn, logn - 1) }
            for elem in expected.0.iter() {
                { *elem }
                { u31ext_equalverify::<QM31Gadget>() }
            }
            for elem in expected.1.iter().rev() {
                { *elem }
                OP_EQUALVERIFY
            }
            OP_TRUE
        };

        println!("FRI.Fiat-Shamir = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_twiddle_merkle_tree() {
        let logn = 5;

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut channel_init_state = [0u8; 32];
        channel_init_state.iter_mut().for_each(|v| *v = prng.gen());

        let proof = {
            let p = CirclePoint::subgroup_gen(logn + 1);

            let evaluation = (0..(1 << logn))
                .map(|i| (p.mul(i * 2 + 1).x.square().square() + 1.into()).into())
                .collect();
            let evaluation = permute_eval(evaluation);

            let proof = fri::fri_prove(&mut Channel::new(channel_init_state), evaluation);
            proof
        };

        let queries = {
            let mut channel = Channel::new(channel_init_state);

            for c in proof.commitments.iter() {
                channel.absorb_commitment(c);
                let _ = channel.draw_element();
            }

            proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));
            channel.draw_5queries(logn).0
        };

        let expected = {
            let mut expected = vec![];

            let twiddle_tree = TwiddleMerkleTree::new(logn - 1);

            for query in queries.iter() {
                expected.extend_from_slice(&twiddle_tree.query(query >> 1).leaf);
            }
            expected
        };

        let script = script! {
            { FRIGadget::push_twiddle_merkle_tree_proof(&proof) }
            for query in queries.iter() {
                { query >> 1 }
            }
            { FRIGadget::check_twiddle_merkle_tree_proof(logn, TWIDDLE_MERKLE_TREE_ROOT_4) }
            for elem in expected.iter().rev() {
                { *elem }
                OP_EQUALVERIFY
            }
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
