use crate::fibonacci::bitcoin_script::FIB_LOG_SIZE;
use crate::fri::FFTGadget;
use crate::merkle_tree::MerkleTreePathGadget;
use crate::treepp::*;
use crate::utils::{
    dup_m31_vec_gadget, hash, hash_m31_vec_gadget, limb_to_be_bits, m31_vec_from_bottom_gadget,
    qm31_reverse,
};
use bitcoin_scriptexec::{profiler_end, profiler_start};
use rust_bitcoin_m31::{
    qm31_add, qm31_copy, qm31_equalverify, qm31_mul, qm31_over, qm31_rot, qm31_swap,
};
use stwo_prover::core::prover::{LOG_BLOWUP_FACTOR, N_QUERIES};

pub struct FibonacciPerQueryFoldGadget;

impl FibonacciPerQueryFoldGadget {
    pub fn run(query_idx: usize) -> Script {
        script! {
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
            //    coeff^6, coeff^5, ..., coeff (6 * 4 = 24)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (15)
            //    answer_1 (qm31)
            //    answer_2 (qm31)

            // pull the query
            { 4 + 4 + 15 + 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8) * N_QUERIES + N_QUERIES - query_idx - 1 } OP_PICK
            { limb_to_be_bits(FIB_LOG_SIZE + LOG_BLOWUP_FACTOR + 1) }
            OP_TOALTSTACK OP_DROP

            // pull y inverse (last twiddle factor)
            8 OP_ROLL

            // local stack (4 elements):
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (14)
            //    answer_1 (qm31)
            //    answer_2 (qm31)
            //    y inverse (1)

            // perform the inverse FFT using p.y inverse
            { FFTGadget::ibutterfly() }

            // obtain circle_poly_alpha
            for _ in 0..4 {
                { 4 + 4 + 14 + 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 - 1 } OP_PICK
            }

            // local stack (4 elements):
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (14)
            //    f1 (qm31)
            //    f2 (qm31)
            //    circle_poly_alpha (qm31)

            qm31_mul qm31_add

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
            //    coeff^6, coeff^5, ..., coeff (6 * 4 = 24)
            //    ---------------------------- per query ----------------------------
            //    twiddle factors (14)
            //    res (qm31)

            for j in 0..FIB_LOG_SIZE as usize {
                // copy the Merkle tree hash
                { 4 + (14 - j) + 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize - (1 + 4) * j - 1 } OP_PICK

                // copy the query
                { 1 + 4 + (14 - j) + 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8) * N_QUERIES + N_QUERIES - query_idx - 1 } OP_PICK

                // push the root hash to the altstack, first
                OP_SWAP OP_TOALTSTACK
                { limb_to_be_bits(FIB_LOG_SIZE + LOG_BLOWUP_FACTOR + 1) }
                OP_DROP
                OP_DROP
                for _ in 0..j {
                    OP_FROMALTSTACK OP_DROP
                }

                // left
                { m31_vec_from_bottom_gadget(4) }
                // duplicate the left
                { dup_m31_vec_gadget(4) }
                qm31_reverse qm31_swap
                // hash the left and keep the hash in the altstack
                { hash_m31_vec_gadget(4) }
                hash
                OP_TOALTSTACK

                // right
                { m31_vec_from_bottom_gadget(4) }
                // duplicate the right
                { dup_m31_vec_gadget(4) }
                qm31_reverse qm31_swap
                // hash the right
                { hash_m31_vec_gadget(4) }
                hash

                // put the left hash out and merge into the parent hash
                OP_FROMALTSTACK
                OP_SWAP
                OP_CAT hash

                { profiler_start("merkle tree verification for folding") }
                { MerkleTreePathGadget::verify((FIB_LOG_SIZE + LOG_BLOWUP_FACTOR - 1) as usize - j) }
                { profiler_end("merkle tree verification for folding") }

                qm31_rot

                OP_FROMALTSTACK
                OP_IF qm31_over
                OP_ELSE { qm31_copy(2) }
                OP_ENDIF

                qm31_equalverify

                { profiler_start("fft and multiply by alpha in folding") }
                8 OP_ROLL
                { FFTGadget::ibutterfly() }

                // obtain the corresponding alpha
                for _ in 0..4 {
                    { 4 + 4 + (14 - 1 - j) + 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize - (1 + 4) * j - 2 } OP_PICK
                }

                qm31_mul qm31_add
                { profiler_end("fft and multiply by alpha in folding") }
            }

            // pull the last layer
            for _ in 0..4 {
                { 4 + (14 - FIB_LOG_SIZE as usize) + 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 - 1 } OP_PICK
            }
            qm31_equalverify

            for _ in 0..(LOG_BLOWUP_FACTOR - 1) {
                OP_DROP
            } // drop the twiddle factors
            for _ in 0..LOG_BLOWUP_FACTOR {
                OP_FROMALTSTACK OP_DROP
            } // drop the unused position bits
        }
    }
}
