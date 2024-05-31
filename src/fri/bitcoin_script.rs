use crate::channel::{Channel, ChannelGadget, ExtractionQM31, ExtractorGadget};
use crate::fri::{FriProof, N_QUERIES};
use crate::merkle_tree::MerkleTreeGadget;
use crate::treepp::*;
use crate::twiddle_merkle_tree::TwiddleMerkleTreeGadget;
use crate::utils::copy_to_altstack_top_item_first_in;
use crate::utils::{limb_to_be_bits, limb_to_be_bits_toaltstack};
use rust_bitcoin_m31::{
    qm31_add, qm31_equalverify, qm31_fromaltstack, qm31_mul, qm31_mul_m31, qm31_over, qm31_roll,
    qm31_sub, qm31_swap, qm31_toaltstack,
};

/// Gadget for FRI.
pub struct FRIGadget;

impl FRIGadget {
    /// Push the hints for Fiat-Shamir.
    pub fn push_fiat_shamir_hints(channel: &mut Channel, logn: usize, proof: &FriProof) -> Script {
        let mut factors_hints = Vec::<ExtractionQM31>::new();

        for c in proof.commitments.iter() {
            channel.absorb_commitment(c);
            let res = channel.draw_qm31();
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
        }
    }

    /// Check the Fiat-Shamir computation.
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
                { ChannelGadget::squeeze_qm31_using_hint() }
                qm31_toaltstack
            }

            for _ in 0..n_last_layer {
                { ChannelGadget::absorb_qm31() }
            }

            { ChannelGadget::squeeze_5queries_using_hint(logn) }

            // remove the channel
            5 OP_ROLL OP_DROP

            for _ in 0..n_layers {
                qm31_fromaltstack
            }
        }
    }

    /// Push all the twiddle Merkle tree proofs.
    pub fn push_twiddle_merkle_tree_proof(fri_proof: &FriProof) -> Script {
        script! {
            for proof in fri_proof.twiddle_merkle_proofs.iter() {
                { TwiddleMerkleTreeGadget::push_twiddle_merkle_tree_proof(proof) }
            }
        }
    }

    /// Check all the twiddle Merkle tree proofs.
    ///
    /// hint: twiddle proof * 5 (as hints)
    /// input: pos * 5
    /// output: leaves * 5
    pub fn check_twiddle_merkle_tree_proof(
        logn: usize,
        twiddle_merkle_tree_root: [u8; 32],
    ) -> Script {
        script! {
            for _ in 0..N_QUERIES {
                OP_TOALTSTACK
            }

            for _ in 0..N_QUERIES {
                { twiddle_merkle_tree_root.to_vec() }
                OP_FROMALTSTACK
                { TwiddleMerkleTreeGadget::query_and_verify(logn) }
            }
        }
    }

    /// Push the several Merkle tree proofs for a specific query.
    pub fn push_single_query_merkle_tree_proof(idx: usize, fri_proof: &FriProof) -> Script {
        script! {
            for proof in fri_proof.merkle_proofs[idx].iter() {
                { proof.leaf }

                for elem in proof.siblings.iter() {
                    { elem.to_vec() }
                }
            }
        }
    }

    /// Check the Merkle tree proofs for each query.
    ///
    /// hints:
    ///   proofs (as hints, larger trees at the beginning)
    /// input:
    ///   roots (as inputs, smaller trees at the beginning),
    ///   query
    ///
    /// output:
    ///   elems
    pub fn check_single_query_merkle_tree_proof(logn: usize) -> Script {
        script! {
            // convert query into bits
            { limb_to_be_bits(logn as u32) }

            // for each of the logn proofs
            for i in (2..=logn).rev() {
                // copy the bits
                { copy_to_altstack_top_item_first_in(i) }

                // copy the root
                { logn } OP_ROLL

                { MerkleTreeGadget::query_and_verify_internal(i, true) }

                qm31_toaltstack
            }

            // drop the bits
            for _ in 0..(logn/2) {
                OP_2DROP
            }

            if logn % 2 == 1 {
                OP_DROP
            }

            // recover all the elements
            for _ in (2..=logn).rev() {
                qm31_fromaltstack
            }
        }
    }

    /// Push the last layer elements from the FRI proof.
    pub fn push_last_layer(fri_proof: &FriProof) -> Script {
        script! {
            for elem in fri_proof.last_layer.iter().rev() {
                { *elem }
            }
        }
    }

    /// Check the ibutterfly stage for one single query.
    ///
    ///  input:
    ///  last_layer (as a given offset)
    ///
    ///  twiddle factors (logn - 1) m31
    ///  alphas (logn - 1) qm31
    ///  siblings (logn - 1) qm31
    ///  leaf qm31
    ///  pos
    ///
    /// output:
    ///  none
    /// mark the transaction as invalid if the check fails
    pub fn check_single_query_ibutterfly(logn: usize, last_layer_offset: usize) -> Script {
        script! {
            { limb_to_be_bits_toaltstack(logn as u32) }

            for i in 1..logn {
                // the top element is right, the second-to-top element is left
                OP_FROMALTSTACK
                OP_NOTIF
                    qm31_swap
                OP_ENDIF

                // pull the twiddle factor
                { 4 * (1 + (logn - i) * 2) } OP_ROLL

                // ibutterfly
                { FFTGadget::ibutterfly() }

                // pull the alpha
                { qm31_roll(1 + (logn - i)) }

                // mul
                qm31_mul

                // add
                qm31_add
            }

            // only work for last layer with 2 elements
            { last_layer_offset - 4 + 4 + 1 }
            OP_FROMALTSTACK
            OP_NOTIF
                4 OP_SUB
            OP_ENDIF

            OP_DUP OP_PICK OP_TOALTSTACK
            OP_1ADD OP_DUP OP_PICK OP_TOALTSTACK
            OP_1ADD OP_DUP OP_PICK OP_TOALTSTACK
            OP_PICK
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK

            qm31_equalverify
        }
    }
}

/// Gadget for FFT.
pub struct FFTGadget;

impl FFTGadget {
    /// Perform inverse butterfly in Bitcoin script.
    /// input:
    ///  v0 (qm31)
    ///  v1 (qm31)
    ///  itwid (m31)
    ///
    /// output:
    ///  v0' (qm31)
    ///  v1' (qm31)
    pub fn ibutterfly() -> Script {
        script! {
            OP_TOALTSTACK

            qm31_over
            qm31_over
            qm31_sub

            OP_FROMALTSTACK
            qm31_mul_m31

            qm31_toaltstack

            qm31_add

            qm31_fromaltstack
        }
    }
}

#[cfg(test)]
mod test {
    use crate::channel::Channel;
    use crate::fri;
    use crate::fri::{FFTGadget, FRIGadget, N_QUERIES};
    use crate::treepp::*;
    use crate::twiddle_merkle_tree::{TwiddleMerkleTree, TWIDDLE_MERKLE_TREE_ROOT_18};
    use crate::utils::permute_eval;
    use bitcoin::hashes::Hash;
    use bitcoin::{TapLeafHash, Transaction};
    use bitcoin_scriptexec::{Exec, ExecCtx, Experimental, Options, TxTemplate};
    use num_traits::One;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rust_bitcoin_m31::qm31_equalverify;
    use stwo_prover::core::circle::CirclePointIndex;
    use stwo_prover::core::fft::ibutterfly;
    use stwo_prover::core::fields::m31::M31;
    use stwo_prover::core::fields::qm31::QM31;
    use stwo_prover::core::fields::FieldExpOps;

    #[test]
    fn test_fiat_shamir() {
        let channel_init_state = {
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let mut channel_init_state = [0u8; 32];
            channel_init_state.iter_mut().for_each(|v| *v = prng.gen());
            channel_init_state
        };

        let mut channel = Channel::new(channel_init_state);
        let logn = 19;

        let proof = {
            let p = CirclePointIndex::subgroup_gen(logn as u32 + 1).to_point();

            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let mut channel_init_state = [0u8; 32];
            channel_init_state.iter_mut().for_each(|v| *v = prng.gen());

            let evaluation = (0..(1 << logn))
                .map(|i| (p.mul(i * 2 + 1).x.square().square() + M31::one()).into())
                .collect();
            let evaluation = permute_eval(evaluation);

            fri::fri_prove(&mut Channel::new(channel_init_state), evaluation)
        };

        let expected = {
            let mut channel = Channel::new(channel_init_state);
            let mut expected_1 = vec![];

            for c in proof.commitments.iter() {
                channel.absorb_commitment(c);
                let res = channel.draw_qm31();
                expected_1.push(res.0);
            }
            proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));

            let res = channel.draw_5queries(logn);

            let expected_2 = res.0;

            (expected_1, expected_2)
        };

        let script = script! {
            { FRIGadget::push_fiat_shamir_hints(&mut channel, logn, &proof) }

            for elem in proof.last_layer.iter().rev() {
                { *elem }
            }
            for c in proof.commitments.iter().rev() {
                { c.clone() }
            }

            { FRIGadget::check_fiat_shamir(&channel_init_state, logn, logn - 1) }
            for elem in expected.0.iter() {
                { *elem }
                qm31_equalverify
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
        let logn = 19;

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut channel_init_state = [0u8; 32];
        channel_init_state.iter_mut().for_each(|v| *v = prng.gen());

        let proof = {
            let p = CirclePointIndex::subgroup_gen(logn as u32 + 1).to_point();

            let evaluation = (0..(1 << logn))
                .map(|i| (p.mul(i * 2 + 1).x.square().square() + M31::one()).into())
                .collect();
            let evaluation = permute_eval(evaluation);

            fri::fri_prove(&mut Channel::new(channel_init_state), evaluation)
        };

        let queries = {
            let mut channel = Channel::new(channel_init_state);

            for c in proof.commitments.iter() {
                channel.absorb_commitment(c);
                let _ = channel.draw_qm31();
            }

            proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));
            channel.draw_5queries(logn).0
        };

        let expected = {
            let mut expected = vec![];

            let twiddle_tree = TwiddleMerkleTree::new(logn - 1);

            for query in queries.iter() {
                expected.extend_from_slice(&twiddle_tree.query(*query).elements);
            }
            expected
        };

        let script = script! {
            { FRIGadget::push_twiddle_merkle_tree_proof(&proof) }
            for query in queries.iter() {
                { *query }
            }
            { FRIGadget::check_twiddle_merkle_tree_proof(logn, TWIDDLE_MERKLE_TREE_ROOT_18) }
            for elem in expected.iter().rev() {
                { *elem }
                OP_EQUALVERIFY
            }
            OP_TRUE
        };

        println!("FRI.Twiddle-Tree = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_single_query_merkle_tree() {
        let logn = 19;

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut channel_init_state = [0u8; 32];
        channel_init_state.iter_mut().for_each(|v| *v = prng.gen());

        let proof = {
            let p = CirclePointIndex::subgroup_gen(logn as u32 + 1).to_point();

            let evaluation = (0..(1 << logn))
                .map(|i| (p.mul(i * 2 + 1).x.square().square() + M31::one()).into())
                .collect();
            let evaluation = permute_eval(evaluation);

            fri::fri_prove(&mut Channel::new(channel_init_state), evaluation)
        };

        let queries = {
            let mut channel = Channel::new(channel_init_state);

            for c in proof.commitments.iter() {
                channel.absorb_commitment(c);
                let _ = channel.draw_qm31();
            }

            proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));
            channel.draw_5queries(logn).0
        };

        let expected = {
            let mut expected = vec![];

            for query in proof.merkle_proofs[0].iter().rev() {
                expected.push(query.leaf);
            }
            expected
        };

        let script = script! {
            { FRIGadget::push_single_query_merkle_tree_proof(0, &proof) }
            for c in proof.commitments.iter().rev() {
                { c.clone() }
            }
            { queries[0] }
            { FRIGadget::check_single_query_merkle_tree_proof(logn) }
            for elem in expected.iter().rev() {
                { *elem }
                qm31_equalverify
            }
            OP_TRUE
        };

        println!("FRI.Single-Query-Tree = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_single_query_butterfly() {
        let logn = 19;

        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut channel_init_state = [0u8; 32];
        channel_init_state.iter_mut().for_each(|v| *v = prng.gen());

        let proof = {
            let p = CirclePointIndex::subgroup_gen(logn as u32 + 1).to_point();

            let evaluation = (0..(1 << logn))
                .map(|i| (p.mul(i * 2 + 1).x.square().square() + M31::one()).into())
                .collect();
            let evaluation = permute_eval(evaluation);

            fri::fri_prove(&mut Channel::new(channel_init_state), evaluation)
        };

        let (alphas, queries) = {
            let mut alphas = vec![];

            let mut channel = Channel::new(channel_init_state);

            for c in proof.commitments.iter() {
                channel.absorb_commitment(c);
                let res = channel.draw_qm31();
                alphas.push(res.0);
            }

            proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));

            let queries = channel.draw_5queries(logn).0;

            (alphas, queries)
        };

        //  last_layer (as hints, last elem first, assuming 2 elements)
        //  twiddle factors (logn - 1) m31
        //  alphas (logn - 1) qm31
        //  siblings (logn - 1) qm31
        //  leaf qm31
        //  pos

        let script = script! {
            { FRIGadget::push_last_layer(&proof) }
            for elem in proof.twiddle_merkle_proofs[0].elements.iter() {
                { *elem }
            }
            for elem in alphas.iter().rev() {
                { *elem }
            }
            for elem in proof.merkle_proofs[0].iter().rev() {
                { elem.leaf }
            }
            { proof.leaves[0] }
            { queries[0] }
            { FRIGadget::check_single_query_ibutterfly(logn, proof.last_layer.len() * 4) }

            { proof.last_layer[0] }
            qm31_equalverify

            { proof.last_layer[1] }
            qm31_equalverify

            OP_TRUE
        };

        println!("FRI.Single-Query-Butterfly = {} bytes", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_end_to_end() {
        let channel_init_state = {
            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let mut channel_init_state = [0u8; 32];
            channel_init_state.iter_mut().for_each(|v| *v = prng.gen());
            channel_init_state
        };

        let mut channel = Channel::new(channel_init_state);
        let logn = 19;

        let proof = {
            let p = CirclePointIndex::subgroup_gen(logn as u32 + 1).to_point();

            let mut prng = ChaCha20Rng::seed_from_u64(0);

            let mut channel_init_state = [0u8; 32];
            channel_init_state.iter_mut().for_each(|v| *v = prng.gen());

            let evaluation = (0..(1 << logn))
                .map(|i| (p.mul(i * 2 + 1).x.square().square() + M31::one()).into())
                .collect();
            let evaluation = permute_eval(evaluation);

            fri::fri_prove(&mut Channel::new(channel_init_state), evaluation)
        };

        let expected_fiat_shamir = {
            let mut channel = Channel::new(channel_init_state);
            let mut expected_1 = vec![];

            for c in proof.commitments.iter() {
                channel.absorb_commitment(c);
                let res = channel.draw_qm31();
                expected_1.push(res.0);
            }
            proof.last_layer.iter().for_each(|v| channel.absorb_qm31(v));

            let res = channel.draw_5queries(logn);

            let expected_2 = res.0;

            (expected_1, expected_2)
        };

        let expected_twiddle_tree = {
            let mut expected = vec![];

            let twiddle_tree = TwiddleMerkleTree::new(logn - 1);

            for query in expected_fiat_shamir.1.iter() {
                expected.extend_from_slice(&twiddle_tree.query(*query).elements);
            }
            expected
        };

        let witness = script! {
            // push all the hints
            { FRIGadget::push_fiat_shamir_hints(&mut channel, logn, &proof) }
            { FRIGadget::push_twiddle_merkle_tree_proof(&proof) }
            for i in 0..N_QUERIES {
                { FRIGadget::push_single_query_merkle_tree_proof(i, &proof) }
            }

            // push the proof body

            // leaves
            for elem in proof.leaves.iter().rev() {
                { *elem }
            }
            // last layer
            for elem in proof.last_layer.iter().rev() {
                { *elem }
            }
            // commitments
            for c in proof.commitments.iter().rev() {
                { c.clone() }
            }
        };

        let script = script! {
            // copy the input for check_fiat_shamir
            for _ in 0..(proof.last_layer.len() * 4 + proof.commitments.len()) {
                { proof.last_layer.len() * 4 + proof.commitments.len() - 1 } OP_PICK
            }

            // do the check_fiat_shamir
            { FRIGadget::check_fiat_shamir(&channel_init_state, logn, logn - 1) }

            // stack:
            //    proof body -- leaves (n_queries qm31), last layer (some qm31), commitments (logn - 1)
            //    5 queries
            //    factors (logn - 1) qm31

            // copy the input for check_twiddle_merkle_tree_proof
            for _ in 0..5 {
                { 5 + (logn - 1) * 4 - 1 } OP_PICK
            }

            { FRIGadget::check_twiddle_merkle_tree_proof(logn, TWIDDLE_MERKLE_TREE_ROOT_18) }

            // stack:
            //    proof body -- leaves (n_queries qm31), last layer (some qm31), commitments (logn - 1)
            //    5 queries
            //    alphas (logn - 1) qm31
            //    twiddle factors 5 * (logn - 1) m31

            // now handle the 1st query, start with the Merkle trees to obtain the siblings
            for i in 0..N_QUERIES {
                // copy the input for check_single_query_merkle_tree
                for _ in 0..logn - 1 {
                    { 5 * (logn - 1) + (logn - 1) * 4 + 5 + (logn - 1) - 1 } OP_PICK
                }

                // copy the query
                { (logn - 1) + 5 * (logn - 1) + (logn - 1) * 4 + 4 - i } OP_PICK

                { FRIGadget::check_single_query_merkle_tree_proof(logn) }

                // stack:
                //    proof body -- leaves (n_queries qm31), last layer (some qm31), commitments (logn - 1)
                //    5 queries
                //    alphas (logn - 1) qm31
                //    twiddle factors 5 * (logn - 1) m31
                //    siblings (logn - 1) qm31

                // copy the input for check
                // move siblings to alt stack
                for _ in 0..(logn - 1) * 4 {
                    OP_TOALTSTACK
                }
                // twiddle factors
                for _ in 0..(logn - 1) {
                    { (4 - i) * (logn - 1) + (logn - 1) - 1 } OP_PICK
                }
                // alphas
                for _ in 0..(logn - 1) * 4 {
                    { (logn - 1) + 5 * (logn - 1) + (logn - 1) * 4 - 1 } OP_PICK
                }
                // siblings
                for _ in 0..(logn - 1) * 4 {
                    OP_FROMALTSTACK
                }
                // leaf
                for _ in 0..4 {
                    { proof.last_layer.len() * 4 + (logn - 1) * (4 + 4 + 4 + 1) + (5 + 1) * (logn - 1) + 5 + 4 - 1 } OP_ROLL
                }
                // position
                { (logn - 1) * (4 + 4 + 1 + 4 + 5) + 4 + (4 - i) } OP_PICK

                { FRIGadget::check_single_query_ibutterfly(logn, (5 + 4 + 1) * (logn - 1) + 5 + proof.last_layer.len() * 4) }

                // stack:
                //    proof body -- leaves (n_queries - i qm31, disappearing), last layer (some qm31), commitments (logn - 1)
                //    5 queries
                //    alphas (logn - 1) qm31
                //    twiddle factors 5 * (logn - 1) m31
            }

            for elem in expected_twiddle_tree.iter().rev() {
                { *elem }
                OP_EQUALVERIFY
            }
            for elem in expected_fiat_shamir.0.iter() {
                { *elem }
                qm31_equalverify
            }
            for elem in expected_fiat_shamir.1.iter().rev() {
                { *elem }
                OP_EQUALVERIFY
            }

            // drop last layer, and commitments
            for _ in 0..((proof.last_layer.len()) * 4 + proof.commitments.len()) {
                OP_DROP
            }

            OP_TRUE
        };

        println!("script length: {}", script.len());

        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options {
                require_minimal: true,
                verify_cltv: true,
                verify_csv: true,
                verify_minimal_if: true,
                enforce_stack_limit: false,
                experimental: Experimental {
                    op_cat: true,
                    op_mul: false,
                    op_div: false,
                },
            },
            TxTemplate {
                tx: Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                },
                prevouts: vec![],
                input_idx: 0,
                taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
            },
            script,
            convert_to_witness(witness).unwrap(),
        )
        .expect("error creating exec");

        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }
        let res = exec.result().unwrap();
        println!("max stack size: {}", exec.stats().max_nb_stack_items);
        assert!(res.success);
    }

    #[test]
    fn test_ibutterfly() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a = QM31::from_m31(
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
        );

        let b = QM31::from_m31(
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
            M31::reduce(prng.next_u64()),
        );

        let itwid = M31::reduce(prng.next_u64());

        let mut v0 = a;
        let mut v1 = b;

        ibutterfly(&mut v0, &mut v1, itwid);

        let script = script! {
            { a }
            { b }
            { itwid }
            { FFTGadget::ibutterfly() }
            { v1 }
            qm31_equalverify
            { v0 }
            qm31_equalverify
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
