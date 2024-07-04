use crate::air::AirGadget;
use crate::channel::Sha256ChannelGadget;
use crate::circle::CirclePointGadget;
use crate::constraints::ConstraintsGadget;
use crate::fibonacci::bitcoin_script::composition::FibonacciCompositionGadget;
use crate::merkle_tree::MerkleTreeTwinGadget;
use crate::oods::OODSGadget;
use crate::pow::PowGadget;
use crate::precomputed_merkle_tree::{
    get_precomputed_merkle_tree_roots, PrecomputedMerkleTreeGadget, PRECOMPUTED_MERKLE_TREE_ROOTS,
};
use crate::{treepp::*, OP_HINT};
use rust_bitcoin_m31::{
    cm31_drop, cm31_equalverify, cm31_from_bottom, qm31_copy, qm31_drop, qm31_dup,
    qm31_equalverify, qm31_from_bottom, qm31_over, qm31_roll,
};
use stwo_prover::core::channel::BWSSha256Channel;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::prover::{LOG_BLOWUP_FACTOR, N_QUERIES, PROOF_OF_WORK_BITS};

mod composition;

const FIB_LOG_SIZE: u32 = 5;

/// A verifier for the Fibonacci proof.
pub struct FibonacciVerifierGadget;

impl FibonacciVerifierGadget {
    /// Run the verifier in the Bitcoin script.
    pub fn run_verifier(channel: &BWSSha256Channel) -> Script {
        let precomputed_merkle_tree_roots =
            PRECOMPUTED_MERKLE_TREE_ROOTS.get_or_init(get_precomputed_merkle_tree_roots);

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

            // stack:
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES)
            //    composition queries (8 * N_QUERIES)
            //    masked points (3 * 8 = 24)
            //    oods point (8)

            // prepare to compute points for trace:
            // - input: p.y, f1(p)
            // - output: a1, b1

            for i in 0..3 {
                for _ in 0..4 {
                    { i * 4 + 8 + (16 - 8 * i) + 4 - 1 } OP_PICK
                }
                for _ in 0..4 {
                    { i * 4 + 4 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 + 16 + (8 - 4 * i) + 4 - 1 } OP_ROLL
                }
                { ConstraintsGadget::column_line_coeffs_with_hint(1) }
            }

            // stack:
            //    composition odds raw values (4 * 4 = 16)
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES)
            //    composition queries (8 * N_QUERIES)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)

            // prepare to compute points for composition:
            // - input: p.y, f1(p), f2(p), f3(p), f4(p)
            // - output: a1, b1, a2, b2, a3, b3, a4, b4

            for _ in 0..4 {
                { 12 + 4 - 1 } OP_PICK
            }
            for _ in 0..16 {
                { 4 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 + 16 - 1 } OP_ROLL
            }
            { ConstraintsGadget::column_line_coeffs_with_hint(4) }

            // stack:
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES)
            //    composition queries (8 * N_QUERIES)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)
            //    (a, b), (a, b), (a, b), (a, b) for composition (4 * 2 * 2 = 16)

            // prepare masked points and oods point for pair vanishing
            for i in 0..4 {
                for _ in 0..8 {
                    { 16 + 12 + 4 * i + (8 + 24) - 8 * i - 1 } OP_PICK
                }
                { ConstraintsGadget::prepare_pair_vanishing_with_hint() }
            }

            // stack:
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES)
            //    composition queries (8 * N_QUERIES)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)
            //    (a, b), (a, b), (a, b), (a, b) for composition (4 * 2 * 2 = 16)
            //    prepared masked points (3 * 4 = 12)
            //    prepared oods point (4)

            // resolve the first point and obtain its twiddle factors
            { 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8) * N_QUERIES + (N_QUERIES - 1) } OP_PICK
            { PrecomputedMerkleTreeGadget::query_and_verify(*precomputed_merkle_tree_roots.get(&(FIB_LOG_SIZE + LOG_BLOWUP_FACTOR)).unwrap(), (FIB_LOG_SIZE + LOG_BLOWUP_FACTOR + 1) as usize) }

            // stack:
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES)
            //    composition queries (8 * N_QUERIES)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)
            //    (a, b), (a, b), (a, b), (a, b) for composition (4 * 2 * 2 = 16)
            //    prepared masked points (3 * 4 = 12)
            //    prepared oods point (4)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    x, y (2)

            // compute the denominator inverses
            for i in 0..4 {
                for _ in 0..4 {
                    { 4 * i + 2 + 15 + (4 + 12) - 4 * i - 1 } OP_PICK // the prepared masked point
                }
                { 4 + 4 * i + 1 } OP_PICK { 4 + 4 * i + 1 } OP_PICK // x, y
                { ConstraintsGadget::denominator_inverse_from_prepared() }
            }

            // stack:
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES)
            //    composition queries (8 * N_QUERIES)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)
            //    (a, b), (a, b), (a, b), (a, b) for composition (4 * 2 * 2 = 16)
            //    prepared masked points (3 * 4 = 12)
            //    prepared oods point (4)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    x, y (2)
            //    denominator inverses (4 * 4 = 16)

            // compute the nominator (before alpha)
            for _ in 0..2 {
                (16 + 2 + 15 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8) * N_QUERIES - 1) OP_ROLL // roll the trace queries
            }
            for _ in 0..4 * 2 {
                (2 + 16 + 2 + 15 + 4 + 12 + 16 + 12 + 8 + 24 + 8 * N_QUERIES - 1) OP_ROLL // roll the composition queries
            }

            // stack:
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES - 2 * 1)
            //    composition queries (8 * N_QUERIES - 8 * 1)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)
            //    (a, b), (a, b), (a, b), (a, b) for composition (4 * 2 * 2 = 16)
            //    prepared masked points (3 * 4 = 12)
            //    prepared oods point (4)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    x, y (2)
            //    denominator inverses (4 * 4 = 16)
            //    trace queries (2)
            //    composition queries (8)

            for i in 0..3 {
                { 4 * i + 8 + 2 + 16 } OP_PICK // copy y
                { 1 + 4 * i + 8 + 2 - 1 } OP_PICK { 1 + 4 * i + 8 + 2 - 1 } OP_PICK // copy trace queries

                for _ in 0..4 {
                    { 3 + 4 * i + 8 + 2 + 16 + 2 + 15 + 4 + 12 + 16 + (12 - 4 * i) - 1 } OP_PICK // copy (a, b)
                }

                { ConstraintsGadget::apply_twin() }
            }

            for i in 0..4 {
                { 4 * i + 12 + 8 + 2 + 16 } OP_PICK // copy y
                { 1 + 4 * i + 12 + (8 - i) - 1 } OP_PICK
                { 1 + 1 + 4 * i + 12 + (4 - i) - 1 } OP_PICK
                // copy composition queries

                for _ in 0..4 {
                    { 3 + 4 * i + 12 + 8 + 2 + 16 + 2 + 15 + 4 + 12 + (16 - 4 * i) - 1 } OP_PICK
                } // copy (a, b)

                { ConstraintsGadget::apply_twin() }
            }

            // stack:
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES - 2 * 1)
            //    composition queries (8 * N_QUERIES - 8 * 1)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)
            //    (a, b), (a, b), (a, b), (a, b) for composition (4 * 2 * 2 = 16)
            //    prepared masked points (3 * 4 = 12)
            //    prepared oods point (4)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    x, y (2)
            //    denominator inverses (4 * 2 * 2 = 16)
            //    trace queries (2)
            //    composition queries (8)
            //    nominators (7 * 2 * 2 = 28)

            // remove the trace queries and composition queries (unused)
            for _ in 0..(2 + 8) {
                28 OP_ROLL OP_DROP
            }

            // remove x, y (unused)
            for _ in 0..2 {
                { 28 + 16 } OP_ROLL OP_DROP
            }

            // test-only: verify the nominators
            for _ in 0..7 * 2 {
                cm31_from_bottom
                cm31_equalverify
            }

            // stack:
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES - 2 * 1)
            //    composition queries (8 * N_QUERIES - 8 * 1)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)
            //    (a, b), (a, b), (a, b), (a, b) for composition (4 * 2 * 2 = 16)
            //    prepared masked points (3 * 4 = 12)
            //    prepared oods point (4)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    denominator inverses (4 * 4 = 16)

            // test-only: clean up the stack
            for _ in 0..4 {
                for _ in 0..2 {
                    cm31_drop
                }
            } // drop the denominator inverses
            for _ in 0..(FIB_LOG_SIZE + LOG_BLOWUP_FACTOR) {
                OP_DROP
            } // drop the twiddle factors
            for _ in 0..16 {
                OP_DROP
            } // drop the prepared points
            for _ in 0..28 {
                OP_DROP
            } // drop the column line coeffs
            { CirclePointGadget::drop() } // drop oods point
            for _ in 0..3 {
                { CirclePointGadget::drop() } // drop masked points
            }
            for _ in 0..(N_QUERIES - 1)  {
                OP_2DROP OP_2DROP OP_2DROP OP_2DROP // drop the queried values for composition
            }
            for _ in 0..(N_QUERIES - 1) {
                OP_2DROP // drop the queried values for trace
            }
            for _ in 0..N_QUERIES {
                OP_DROP // drop the queries (out of order)
            }
            qm31_drop // drop the last layer eval
            for _ in 0..FIB_LOG_SIZE {
                qm31_drop // drop the derived folding_alpha
                OP_DROP // drop the commitment
            }
            qm31_drop // drop circle_poly_alpha
            qm31_drop // drop random_coeff2
        }
    }
}

#[cfg(test)]
mod test {
    use crate::fibonacci::bitcoin_script::FIB_LOG_SIZE;
    use crate::fibonacci::{verify_with_hints, FibonacciVerifierGadget};
    use crate::treepp::*;
    use stwo_prover::core::channel::{BWSSha256Channel, Channel};
    use stwo_prover::core::fields::m31::{BaseField, M31};
    use stwo_prover::core::fields::IntoSlice;
    use stwo_prover::core::prover::prove;
    use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hasher;
    use stwo_prover::core::vcs::hasher::Hasher;
    use stwo_prover::examples::fibonacci::Fibonacci;

    #[test]
    fn test_verifier() {
        let fib = Fibonacci::new(FIB_LOG_SIZE, M31::reduce(443693538));

        let trace = fib.get_trace();
        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        let proof = prove(&fib.air, channel, vec![trace]).unwrap();

        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        let channel_clone = channel.clone();

        let hint = verify_with_hints(proof, &fib.air, channel).unwrap();

        let witness = script! {
            { hint }
        };

        let script = script! {
            { FibonacciVerifierGadget::run_verifier(&channel_clone) }
            OP_TRUE
        };

        let exec_result = execute_script_with_witness_unlimited_stack(
            script,
            convert_to_witness(witness).unwrap(),
        );
        assert!(exec_result.success);
    }
}
