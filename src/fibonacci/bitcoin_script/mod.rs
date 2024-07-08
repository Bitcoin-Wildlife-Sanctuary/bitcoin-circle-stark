use crate::circle::CirclePointGadget;
use crate::constraints::ConstraintsGadget;
use crate::fibonacci::bitcoin_script::fiat_shamir::FibonacciFiatShamirGadget;
use crate::fri::{FFTGadget, FieldInversionGadget};
use crate::precomputed_merkle_tree::{
    get_precomputed_merkle_tree_roots, PrecomputedMerkleTreeGadget, PRECOMPUTED_MERKLE_TREE_ROOTS,
};
use crate::treepp::*;
use rust_bitcoin_m31::{
    cm31_add, cm31_fromaltstack, cm31_mul, cm31_roll, cm31_toaltstack, qm31_add, qm31_drop,
    qm31_dup, qm31_equalverify, qm31_from_bottom, qm31_fromaltstack, qm31_mul, qm31_mul_cm31,
    qm31_over, qm31_rot, qm31_square, qm31_swap, qm31_toaltstack,
};
use stwo_prover::core::channel::BWSSha256Channel;
use stwo_prover::core::prover::{LOG_BLOWUP_FACTOR, N_QUERIES};

mod composition;

mod fiat_shamir;

const FIB_LOG_SIZE: u32 = 5;

/// A verifier for the Fibonacci proof.
pub struct FibonacciVerifierGadget;

impl FibonacciVerifierGadget {
    /// Run the verifier in the Bitcoin script.
    pub fn run_verifier(channel: &BWSSha256Channel) -> Script {
        let precomputed_merkle_tree_roots =
            PRECOMPUTED_MERKLE_TREE_ROOTS.get_or_init(get_precomputed_merkle_tree_roots);

        script! {
            // Run the Fiat-Shamir gadget
            { FibonacciFiatShamirGadget::run(channel) }

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

            // move random_coeffs2 closer
            for _ in 0..4 {
                { 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 - 1 } OP_ROLL
            }

            // compute coeff^6, coeff^5, coeff^4, coeff^3, coeff^2, coeff
            qm31_dup qm31_toaltstack
            qm31_dup qm31_square qm31_dup qm31_toaltstack
            qm31_over qm31_mul qm31_dup qm31_toaltstack
            qm31_over qm31_mul qm31_dup qm31_toaltstack
            qm31_over qm31_mul qm31_dup qm31_toaltstack
            qm31_mul qm31_fromaltstack qm31_fromaltstack qm31_fromaltstack qm31_fromaltstack qm31_fromaltstack

            // stack:
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
            //    coeff^6, coeff^5, ..., coeff (24)

            // resolve the first point and obtain its twiddle factors
            { 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8) * N_QUERIES + (N_QUERIES - 1) } OP_PICK
            { PrecomputedMerkleTreeGadget::query_and_verify(*precomputed_merkle_tree_roots.get(&(FIB_LOG_SIZE + LOG_BLOWUP_FACTOR)).unwrap(), (FIB_LOG_SIZE + LOG_BLOWUP_FACTOR + 1) as usize) }

            // stack:
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
            //    coeff^6, coeff^5, ..., coeff (24)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    x, y (2)

            // compute the denominator inverses
            for i in 0..4 {
                for _ in 0..4 {
                    { 4 * i + 2 + 15 + (24 + 4 + 12) - 4 * i - 1 } OP_PICK // the prepared masked point
                }
                { 4 + 4 * i + 1 } OP_PICK { 4 + 4 * i + 1 } OP_PICK // x, y
                { ConstraintsGadget::denominator_inverse_from_prepared() }
            }

            // stack:
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
            //    coeff^6, coeff^5, ..., coeff (24)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    x, y (2)
            //    denominator inverses (4 * 4 = 16)

            // compute the nominator (before alpha)
            for _ in 0..2 {
                (16 + 2 + 15 + 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8) * N_QUERIES - 1) OP_ROLL // roll the trace queries
            }
            for _ in 0..4 * 2 {
                (2 + 16 + 2 + 15 + 24 + 4 + 12 + 16 + 12 + 8 + 24 + 8 * N_QUERIES - 1) OP_ROLL // roll the composition queries
            }

            // stack:
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
            //    coeff^6, coeff^5, ..., coeff (24)
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
                    { 3 + 4 * i + 8 + 2 + 16 + 2 + 15 + 24 + 4 + 12 + 16 + (12 - 4 * i) - 1 } OP_PICK // copy (a, b)
                }

                { ConstraintsGadget::apply_twin() }
            }

            for i in 0..4 {
                { 4 * i + 12 + 8 + 2 + 16 } OP_PICK // copy y
                { 1 + 4 * i + 12 + (8 - i) - 1 } OP_PICK
                { 1 + 1 + 4 * i + 12 + (4 - i) - 1 } OP_PICK
                // copy composition queries

                for _ in 0..4 {
                    { 3 + 4 * i + 12 + 8 + 2 + 16 + 2 + 15 + 24 + 4 + 12 + (16 - 4 * i) - 1 } OP_PICK
                } // copy (a, b)

                { ConstraintsGadget::apply_twin() }
            }

            // stack:
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
            //    coeff^6, coeff^5, ..., coeff (24)
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

            // remove x (unused)
            { 28 + 16 + 1 } OP_ROLL OP_DROP

            // stack:
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
            //    coeff^6, coeff^5, ..., coeff (6 * 4 = 24)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    y (1)
            //    denominator inverses (4 * 2 * 2 = 16)
            //    nominators (7 * 2 * 2 = 28)

            // u1, u2, u3:
            //   nominator[0, 1, 2].left * denominator_inverses[0].left

            // local stack:
            //    denominator inverses (8 cm31): u1, v1, u2, v2, u3, v3, u4, v4
            //    nominators (14 cm31):
            //      a1, b1, a2, b2, a3, b3, c1, d1, c2, d2, c3, d3, c4, d4

            { cm31_roll(14 + 8 - 1) } // u1
            { cm31_roll(1 + 14 - 1) } // a1
            cm31_mul cm31_toaltstack // u1 * a1

            { cm31_roll(13 + 8 - 3) } // u2
            { cm31_roll(1 + 14 - 3) } // a2
            cm31_mul cm31_toaltstack // u2 * a2

            { cm31_roll(12 + 8 - 5) } // u3
            { cm31_roll(1 + 14 - 5) } // a3
            cm31_mul cm31_toaltstack // u3 * a3

            // local stack:
            //    denominator inverses (5 cm31): v1, v2, v3, u4, v4
            //    nominators (11 cm31):
            //      b1, b2, b3, c1, d1, c2, d2, c3, d3, c4, d4
            //
            // local altstack:
            //      u1 * a1 (cm31), u2 * a2 (cm31), u3 * a3 (cm31)

            { cm31_roll(11 + 5 - 1) } // v1
            { cm31_roll(1 + 11 - 1) } // b1
            cm31_mul cm31_toaltstack // v1 * b1

            { cm31_roll(10 + 5 - 2) } // v2
            { cm31_roll(1 + 11 - 2) } // b2
            cm31_mul cm31_toaltstack // v2 * b2

            { cm31_roll(9 + 5 - 3) } // v3
            { cm31_roll(1 + 11 - 3) } // b3
            cm31_mul cm31_toaltstack // v3 * b3

            // local stack:
            //    denominator inverses (2 cm31): u4, v4
            //    nominators (8 cm31):
            //      c1, d1, c2, d2, c3, d3, c4, d4
            //
            // local altstack:
            //      u1 * a1 (cm31), u2 * a2 (cm31), u3 * a3 (cm31)
            //      v1 * b1 (cm31), v2 * b2 (cm31), v3 * b3 (cm31)

            for _ in 0..4 {
                { (8 + 2) * 2 + 1 + 15 + 12 - 1 } OP_PICK
            } // copy coeff^3
            { cm31_roll(2 + 8 - 1) } // c1
            qm31_mul_cm31 qm31_toaltstack

            for _ in 0..4 {
                { (7 + 2) * 2 + 1 + 15 + 8 - 1 } OP_PICK
            } // copy coeff^2
            { cm31_roll(2 + 6 - 1) } // c2
            qm31_mul_cm31 qm31_toaltstack

            for _ in 0..4 {
                { (6 + 2) * 2 + 1 + 15 + 4 - 1 } OP_PICK
            } // copy coeff
            { cm31_roll(2 + 4 - 1) } // c3
            qm31_mul_cm31

            qm31_fromaltstack qm31_add
            qm31_fromaltstack qm31_add
            { cm31_roll(2 + 1) } // c4
            cm31_add

            { cm31_roll(2 + 4 + 1) } // u4
            qm31_mul_cm31
            qm31_toaltstack

            // local stack:
            //    denominator inverse: v4
            //    nominators (4 cm31):
            //      d1, d2, d3, d4
            //
            // local altstack:
            //      u1 * a1 (cm31), u2 * a2 (cm31), u3 * a3 (cm31)
            //      v1 * b1 (cm31), v2 * b2 (cm31), v3 * b3 (cm31)
            //      (coeff^3 * c1 + coeff^2 * c2 + coeff * c3 + c4) * u4 (qm31)

            for _ in 0..4 {
                { (4 + 1) * 2 + 1 + 15 + 12 - 1 } OP_PICK
            } // copy coeff^3
            { cm31_roll(2 + 4 - 1) } // d1
            qm31_mul_cm31 qm31_toaltstack

            for _ in 0..4 {
                { (3 + 1) * 2 + 1 + 15 + 8 - 1 } OP_PICK
            } // copy coeff^2
            { cm31_roll(2 + 3 - 1) } // d2
            qm31_mul_cm31 qm31_toaltstack

            for _ in 0..4 {
                { (2 + 1) * 2 + 1 + 15 + 4 - 1 } OP_PICK
            } // copy coeff
            { cm31_roll(2 + 2 - 1) } // d3
            qm31_mul_cm31

            qm31_fromaltstack qm31_add
            qm31_fromaltstack qm31_add
            { cm31_roll(2) } // d4
            cm31_add

            { cm31_roll(2) } // v4
            qm31_mul_cm31
            qm31_toaltstack

            // local stack:
            // local altstack:
            //      u1 * a1 (cm31), u2 * a2 (cm31), u3 * a3 (cm31)
            //      v1 * b1 (cm31), v2 * b2 (cm31), v3 * b3 (cm31)
            //      (coeff^3 * c1 + coeff^2 * c2 + coeff * c3 + c4) * u4 (qm31)
            //      (coeff^3 * d1 + coeff^2 * d2 + coeff * d3 + d4) * v4 (qm31)

            qm31_fromaltstack qm31_fromaltstack
            for _ in 0..6 {
                cm31_fromaltstack
            }

            // local stack (6 * 2 + 2 * 4 = 20 elements):
            //      (coeff^3 * d1 + coeff^2 * d2 + coeff * d3 + d4) * v4 (qm31)
            //      (coeff^3 * c1 + coeff^2 * c2 + coeff * c3 + c4) * u4 (qm31)
            //      v3 * b3 (cm31), v2 * b2 (cm31), v1 * b1 (cm31),
            //      u3 * a3 (cm31), u2 * a2 (cm31), u1 * a1 (cm31)

            for _ in 0..4 {
                { 20 + 1 + 15 + 24 - 1 } OP_PICK
            } // copy coeff^6
            { cm31_roll(2) } // u1 * a1
            qm31_mul_cm31 qm31_toaltstack

            for _ in 0..4 {
                { 18 + 1 + 15 + 20 - 1 } OP_PICK
            } // copy coeff^5
            { cm31_roll(2) } // u2 * a2
            qm31_mul_cm31 qm31_toaltstack

            for _ in 0..4 {
                { 16 + 1 + 15 + 16 - 1 } OP_PICK
            } // copy coeff^4
            { cm31_roll(2) } // u3 * a3
            qm31_mul_cm31

            qm31_fromaltstack qm31_add qm31_fromaltstack qm31_add
            qm31_toaltstack

            for _ in 0..4 {
                { 14 + 1 + 15 + 24 - 1 } OP_PICK
            } // copy coeff^6
            { cm31_roll(2) } // v1 * b1
            qm31_mul_cm31 qm31_toaltstack

            for _ in 0..4 {
                { 12 + 1 + 15 + 20 - 1 } OP_PICK
            } // copy coeff^5
            { cm31_roll(2) } // v2 * b2
            qm31_mul_cm31 qm31_toaltstack

            for _ in 0..4 {
                { 10 + 1 + 15 + 16 - 1 } OP_PICK
            } // copy coeff^4
            { cm31_roll(2) } // v3 * b3
            qm31_mul_cm31

            qm31_fromaltstack qm31_add qm31_fromaltstack qm31_add
            qm31_fromaltstack

            qm31_rot qm31_add
            qm31_toaltstack qm31_add qm31_fromaltstack qm31_swap

            // local stack (4 elements):
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    y (1)
            //    answer_1 (qm31)
            //    answer_2 (qm31)

            // pull y and compute its inverse
            8 OP_ROLL
            { FieldInversionGadget::inverse_with_hint() }

            // local stack (4 elements):
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    answer_1 (qm31)
            //    answer_2 (qm31)
            //    y inverse (1)

            // perform the inverse FFT using p.y inverse
            { FFTGadget::ibutterfly() }

            // test only: check the result consistency
            qm31_from_bottom qm31_equalverify
            qm31_from_bottom qm31_equalverify

            // stack:
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
            //    random_coeff2 (4)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)

            // test-only: clean up the stack
            for _ in 0..(FIB_LOG_SIZE + LOG_BLOWUP_FACTOR) {
                OP_DROP
            } // drop the twiddle factors
            for _ in 0..6 {
                qm31_drop
            } // drop coeff^6, coeff^5, ..., coeff
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
    use stwo_prover::core::prover::{prove, verify};
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

        {
            let channel =
                &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                    .air
                    .component
                    .claim])));
            verify(proof.clone(), &fib.air, channel).unwrap();
        }

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
