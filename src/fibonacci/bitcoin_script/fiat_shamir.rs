use crate::air::AirGadget;
use crate::channel::Sha256ChannelGadget;
use crate::circle::CirclePointGadget;
use crate::fibonacci::bitcoin_script::composition::FibonacciCompositionGadget;
use crate::fibonacci::bitcoin_script::FIB_LOG_SIZE;
use crate::merkle_tree::MerkleTreeTwinGadget;
use crate::oods::OODSGadget;
use crate::pow::PowGadget;
use crate::treepp::*;
use crate::OP_HINT;
use rust_bitcoin_m31::{
    qm31_copy, qm31_dup, qm31_equalverify, qm31_from_bottom, qm31_over, qm31_roll,
};
use stwo_prover::core::channel::BWSSha256Channel;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::prover::{LOG_BLOWUP_FACTOR, N_QUERIES, PROOF_OF_WORK_BITS};

pub struct FibonacciFiatShamirGadget;

impl FibonacciFiatShamirGadget {
    /// Finish the Fiat-Shamir transform steps until finalizing the queries.
    ///
    /// Hint:
    /// - trace commitment and composition commitment
    /// - first random coeff hint, used for constructing the composition polynomial
    /// - OODS hint, used for extraction
    /// - trace OODS sample values
    /// - composition OODS sample values
    /// - composition hint, used for evaluating the composition (see `FibonacciCompositionGadget`)
    /// - second random coeff hint, used for aggregating the FRI answers
    /// - circle poly alpha hint, used for the first FRI step
    /// - FRI commitments and folding hints, which are commitments of the FRI intermediate trees and
    ///   hints for extracting the corresponding folding alpha
    /// - last layer value, assuming only one QM31 element
    /// - PoW hint, used for verifying the PoW
    /// - queries sampling hints, used to sample the `N_QUERIES` queries
    ///
    /// Input: none
    ///
    /// Output:
    /// - trace oods values (3 * 4 = 12)
    /// - composition odds raw values (4 * 4 = 16)
    /// - random_coeff2 (4)
    /// - circle_poly_alpha (4)
    /// - (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
    /// - last layer (4)
    /// - queries (N_QUERIES)
    /// - trace queries (2 * N_QUERIES)
    /// - composition queries (8 * N_QUERIES)
    /// - masked points (3 * 8 = 24)
    /// - oods point (8)
    ///
    pub fn run(channel: &BWSSha256Channel) -> Script {
        script! {
            // push the initial channel
            { channel.digest }

            // pull the first commitment and mix it with the channel
            OP_HINT
            OP_DUP OP_ROT
            { Sha256ChannelGadget::mix_digest() }

            // draw random_coeff
            { Sha256ChannelGadget::draw_felt_with_hint() }

            4 OP_ROLL

            // pull the second commitment and mix it with the channel
            OP_HINT
            OP_DUP OP_ROT
            { Sha256ChannelGadget::mix_digest() }

            // draw the OODS point
            { OODSGadget::get_random_point() }

            // stack: c1, random_coeff (4), c2, channel_digest, oods point (8)
            { CirclePointGadget::dup() }

            // mask the points
            { AirGadget::shifted_mask_points(&vec![vec![0, 1, 2]], &[CanonicCoset::new(FIB_LOG_SIZE)]) }

            // pull trace oods values from the hint
            for _ in 0..3 {
                qm31_from_bottom
            }

            // pull the composition oods raw values from the hint
            for _ in 0..4 {
                qm31_from_bottom
            }

            // stack:
            //    c1, random_coeff (4), c2, channel_digest, oods point (8),
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)

            // update the digest with all the trace oods values and composition odds raw values

            60 OP_ROLL OP_TOALTSTACK
            { qm31_copy(6) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(5) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(4) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(3) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(2) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            qm31_over OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            qm31_dup OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK

            // compute the composition eval
            //
            // stack:
            //    c1, random_coeff (4), c2, oods point (8),
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //
            // altstack:
            //    channel_digest

            { qm31_copy(3) }
            { qm31_copy(3) }
            { qm31_copy(3) }
            { qm31_copy(3) }
            { AirGadget::eval_from_partial_evals() }

            // prepare the input to `eval_composition_polynomial_at_point`
            //
            // stack:
            //    c1, random_coeff (4), c2, oods point (8)
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    composition odds value (4)
            //
            // altstack:
            //    channel_digest

            64 OP_ROLL OP_TOALTSTACK
            { qm31_roll(16) }
            { qm31_copy(8) }
            { qm31_copy(8) }
            { qm31_copy(8) }
            { qm31_copy(19) }
            { qm31_copy(19) }

            // stack:
            //    c1, oods point (8)
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    composition odds value (4)
            //
            //    random_coeff (4)
            //    trace oods values (3 * 4 = 12)
            //    oods point (8)
            //
            // altstack:
            //    channel_digest, c2

            { FibonacciCompositionGadget::eval_composition_polynomial_at_point(FIB_LOG_SIZE, M31::from_u32_unchecked(443693538)) }

            qm31_equalverify

            OP_FROMALTSTACK OP_FROMALTSTACK

            // obtain random_coeff2 and circle_poly_alpha
            { Sha256ChannelGadget::draw_felt_with_hint() }
            4 OP_ROLL { Sha256ChannelGadget::draw_felt_with_hint() }
            4 OP_ROLL

            // compute all the intermediate alphas
            //
            // stack:
            //    c1, oods point (8)
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    c2
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    channel_digest

            for _ in 0..FIB_LOG_SIZE {
                OP_HINT OP_DUP OP_ROT { Sha256ChannelGadget::mix_digest() }
                { Sha256ChannelGadget::draw_felt_with_hint() }
                4 OP_ROLL
            }

            // stack:
            //    c1, oods point (8)
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    c2
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    channel_digest

            // incorporate the last layer
            qm31_from_bottom
            qm31_dup
            8 OP_ROLL
            { Sha256ChannelGadget::mix_felt() }

            // stack:
            //    c1, oods point (8)
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    c2
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    channel_digest

            // check proof of work
            { PowGadget::verify_pow(PROOF_OF_WORK_BITS) }

            // derive N_QUERIES queries
            { Sha256ChannelGadget::draw_numbers_with_hint(N_QUERIES, (FIB_LOG_SIZE + LOG_BLOWUP_FACTOR + 1) as usize) }

            // drop channel digest
            { N_QUERIES } OP_ROLL OP_DROP

            // stack:
            //    c1, oods point (8)
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    c2
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)

            // pull c1, which is the commitment of the trace Merkle tree
            { N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 + 1 + 16 + 12 + 24 + 8 } OP_ROLL

            // stack:
            //    oods point (8)
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    c2
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    c1

            // handle each query for trace
            for i in 0..N_QUERIES {
                { 2 * i } OP_PICK // copy c1
                { 2 * i + 1 + 1 + N_QUERIES - i - 1 } OP_PICK // copy query
                { MerkleTreeTwinGadget::query_and_verify(1, (FIB_LOG_SIZE + LOG_BLOWUP_FACTOR + 1) as usize) }
            }

            // drop c1
            { 2 * N_QUERIES } OP_ROLL OP_DROP

            // stack:
            //    oods point (8)
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    c2
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES)

            // pull c2, which is the commitment of the composition Merkle tree
            { 2 * N_QUERIES + N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 } OP_ROLL

            // handle each query for composition
            for i in 0..N_QUERIES {
                { 8 * i } OP_PICK // copy c2
                { 1 + 8 * i + 1 + 2 * N_QUERIES + N_QUERIES - i - 1 } OP_PICK // copy query
                { MerkleTreeTwinGadget::query_and_verify(4, (FIB_LOG_SIZE + LOG_BLOWUP_FACTOR + 1) as usize) }
            }

            // drop c2
            { 8 * N_QUERIES } OP_ROLL OP_DROP

            // stack:
            //    oods point (8)
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES)
            //    composition queries (8 * N_QUERIES)

            // pull the masked points
            for _ in 0..24 {
                { (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 + 16 + 12 + 24 - 1 } OP_ROLL
            }

            // pull the OODS point
            for _ in 0..8 {
                { 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 + 16 + 12 + 8 - 1 } OP_ROLL
            }
        }
    }
}
