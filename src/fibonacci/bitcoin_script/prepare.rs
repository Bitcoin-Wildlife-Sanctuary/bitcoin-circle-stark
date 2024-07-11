use crate::constraints::ConstraintsGadget;
use crate::treepp::*;
use rust_bitcoin_m31::{
    qm31_dup, qm31_fromaltstack, qm31_mul, qm31_over, qm31_square, qm31_toaltstack,
};
use stwo_prover::core::prover::N_QUERIES;

const FIB_LOG_SIZE: u32 = 5;

/// Prepare Gadget
pub struct FibonacciPrepareGadget;

impl FibonacciPrepareGadget {
    pub fn run() -> Script {
        script! {
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
        }
    }
}
