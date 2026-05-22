//! Histogram every opcode in the compiled Plonk verifier scripts and
//! group the counts into semantic buckets so we can see where bytes go
//! under the `free-mul` hypothetical.
//!
//! Buckets (rough):
//!   stack_plumbing : OP_PICK, OP_ROLL, OP_DUP, OP_OVER, OP_SWAP, OP_ROT,
//!                    OP_TOALTSTACK, OP_FROMALTSTACK, OP_DROP, OP_2DROP,
//!                    OP_NIP, OP_TUCK, OP_IFDUP, OP_DEPTH, OP_1SUB, OP_1ADD.
//!                    In the free-mul world most of this is LDM and
//!                    covenant-split state plumbing.
//!   hash_work      : OP_SHA256, OP_HASH160, OP_HASH256, OP_RIPEMD160,
//!                    OP_CAT — the actual hash computation + byte-string
//!                    concatenation (channel, merkle, fiat-shamir, LDM).
//!   arith          : OP_ADD, OP_SUB, OP_NEGATE, OP_ABS, OP_BOOLAND/OR,
//!                    OP_NOT, OP_0NOTEQUAL.
//!   compare        : OP_EQUAL, OP_EQUALVERIFY, OP_LESSTHAN, OP_GREATERTHAN,
//!                    OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_NUMEQUAL,
//!                    OP_NUMEQUALVERIFY, OP_VERIFY, OP_IF, OP_ELSE, OP_ENDIF,
//!                    OP_NOTIF, OP_SIZE.
//!   push_data      : OP_0, OP_1NEGATE, OP_1..OP_16, OP_PUSHBYTES_* payloads.
//!                    Witness-embedded constants.
//!
//! This gives us a rough picture without needing to patch the DSL.

use bitcoin_circle_stark::dsl::plonk::{
    hints::Hints, part1_fiat_shamir1, part2_fiat_shamir2_and_constraint_num,
    part3_constraint_denom, part4_pair_vanishing_and_alphas, part5_column_line_coeffs1,
    part6_column_line_coeffs2, part7_column_line_coeffs3, part8_cleanup, per_query_part1_folding,
    per_query_part2_num_trace, per_query_part3_num_constant, per_query_part4_num_composition,
    per_query_part5_num_interaction_shifted, per_query_part6_num_interaction1,
    per_query_part7_num_interaction2, per_query_part8_last_step,
};
use bitcoin_script_dsl::compiler::Compiler;
use bitcoin_script_dsl::ldm::LDM;
use std::collections::BTreeMap;

#[derive(Default, Clone)]
struct Buckets {
    stack_plumbing: usize,
    hash_work: usize,
    arith: usize,
    compare: usize,
    push_data: usize,
    other: usize,
    total: usize,
    // opcode-specific sub-counts
    op_pick: usize,
    op_roll: usize,
    op_sha256: usize,
    op_cat: usize,
    op_equalverify: usize,
    op_dup: usize,
    op_toaltstack: usize,
    op_fromaltstack: usize,
    op_add: usize,
    op_sub: usize,
    op_mul: usize,
    op_mod: usize,
}

impl Buckets {
    fn add(&mut self, o: &Buckets) {
        self.stack_plumbing += o.stack_plumbing;
        self.hash_work += o.hash_work;
        self.arith += o.arith;
        self.compare += o.compare;
        self.push_data += o.push_data;
        self.other += o.other;
        self.total += o.total;
        self.op_pick += o.op_pick;
        self.op_roll += o.op_roll;
        self.op_sha256 += o.op_sha256;
        self.op_cat += o.op_cat;
        self.op_equalverify += o.op_equalverify;
        self.op_dup += o.op_dup;
        self.op_toaltstack += o.op_toaltstack;
        self.op_fromaltstack += o.op_fromaltstack;
        self.op_add += o.op_add;
        self.op_sub += o.op_sub;
        self.op_mul += o.op_mul;
        self.op_mod += o.op_mod;
    }
}

fn classify(script: &[u8]) -> Buckets {
    let mut b = Buckets {
        total: script.len(),
        ..Default::default()
    };

    let mut i = 0;
    while i < script.len() {
        let op = script[i];

        // OP_PUSHBYTES_1..OP_PUSHBYTES_75 (0x01..0x4b): raw data pushes.
        if (0x01..=0x4b).contains(&op) {
            let payload = op as usize;
            b.push_data += 1 + payload;
            i += 1 + payload;
            continue;
        }
        // OP_PUSHDATA1 (0x4c): next byte is length.
        if op == 0x4c {
            let payload = script[i + 1] as usize;
            b.push_data += 2 + payload;
            i += 2 + payload;
            continue;
        }
        // OP_PUSHDATA2 (0x4d): next 2 bytes length.
        if op == 0x4d {
            let payload = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
            b.push_data += 3 + payload;
            i += 3 + payload;
            continue;
        }

        // Single-byte opcodes from here on.
        match op {
            // Numeric push short-forms
            0x00 /* OP_0 */
            | 0x4f /* OP_1NEGATE */
            | 0x51..=0x60 /* OP_1..OP_16 */ => b.push_data += 1,

            // Stack plumbing: OP_TOALTSTACK(0x6b)..OP_TUCK(0x7d) contiguous range.
            0x6b..=0x7d => {
                b.stack_plumbing += 1;
                match op {
                    0x79 => b.op_pick += 1,
                    0x7a => b.op_roll += 1,
                    0x76 => b.op_dup += 1,
                    0x6b => b.op_toaltstack += 1,
                    0x6c => b.op_fromaltstack += 1,
                    _ => {}
                }
            }

            // Hash work + concatenation
            0xa6 /* RIPEMD160 */ | 0xa7 /* SHA1 */ | 0xa8 /* SHA256 */
            | 0xa9 /* HASH160 */ | 0xaa /* HASH256 */ | 0x7e /* OP_CAT */ => {
                b.hash_work += 1;
                if op == 0xa8 { b.op_sha256 += 1; }
                if op == 0x7e { b.op_cat += 1; }
            }

            // Arithmetic
            0x8b /* OP_1ADD */ | 0x8c /* OP_1SUB */
            | 0x8f /* OP_NEGATE */ | 0x90 /* OP_ABS */
            | 0x91 /* OP_NOT */ | 0x92 /* OP_0NOTEQUAL */
            | 0x93 /* OP_ADD */ | 0x94 /* OP_SUB */ | 0x95 /* OP_MUL */
            | 0x96 /* OP_DIV */ | 0x97 /* OP_MOD */
            | 0xa1 /* OP_BOOLAND */ | 0xa2 /* OP_BOOLOR */ => {
                b.arith += 1;
                match op {
                    0x93 => b.op_add += 1,
                    0x94 => b.op_sub += 1,
                    0x95 => b.op_mul += 1,
                    0x97 => b.op_mod += 1,
                    _ => {}
                }
            }

            // Comparison + control flow
            0x82 /* OP_SIZE */ | 0x87 /* OP_EQUAL */ | 0x88 /* OP_EQUALVERIFY */
            | 0x9c /* OP_NUMEQUAL */ | 0x9d /* OP_NUMEQUALVERIFY */
            | 0x9f /* OP_LESSTHAN */ | 0xa0 /* OP_GREATERTHAN */
            | 0xa3 /* OP_LESSTHANOREQUAL */ | 0xa4 /* OP_GREATERTHANOREQUAL */
            | 0xa5 /* OP_MIN */ | 0x9e /* OP_NUMNOTEQUAL */
            | 0x63 /* OP_IF */ | 0x64 /* OP_NOTIF */ | 0x67 /* OP_ELSE */
            | 0x68 /* OP_ENDIF */ | 0x69 /* OP_VERIFY */ | 0x6a /* OP_RETURN */ => {
                b.compare += 1;
                if op == 0x88 { b.op_equalverify += 1; }
            }

            _ => {
                b.other += 1;
            }
        }

        i += 1;
    }

    b
}

fn main() {
    let hints = Hints::instance();
    let mut ldm = LDM::new();

    let mut total = Buckets::default();
    let mut per_part: BTreeMap<String, Buckets> = BTreeMap::new();

    let mut measure =
        |name: &str, cs: bitcoin_script_dsl::constraint_system::ConstraintSystemRef| {
            let program = Compiler::compile(cs).unwrap();
            let b = classify(program.script.as_bytes());
            total.add(&b);
            per_part.insert(name.to_string(), b);
        };

    macro_rules! run_fixed {
        ($name:expr, $f:path) => {{
            let cs = $f(&hints, &mut ldm).unwrap();
            measure($name, cs);
        }};
    }
    macro_rules! run_per_query {
        ($name:expr, $f:path, $q:expr) => {{
            let cs = $f(&hints, &mut ldm, $q).unwrap();
            measure($name, cs);
        }};
    }

    run_fixed!("part1_fiat_shamir1", part1_fiat_shamir1::generate_cs);
    run_fixed!(
        "part2_fiat_shamir2_and_constraint_num",
        part2_fiat_shamir2_and_constraint_num::generate_cs
    );
    run_fixed!(
        "part3_constraint_denom",
        part3_constraint_denom::generate_cs
    );
    run_fixed!(
        "part4_pair_vanishing_and_alphas",
        part4_pair_vanishing_and_alphas::generate_cs
    );
    run_fixed!(
        "part5_column_line_coeffs1",
        part5_column_line_coeffs1::generate_cs
    );
    run_fixed!(
        "part6_column_line_coeffs2",
        part6_column_line_coeffs2::generate_cs
    );
    run_fixed!(
        "part7_column_line_coeffs3",
        part7_column_line_coeffs3::generate_cs
    );

    for q in 0..8 {
        run_per_query!(
            &format!("per_query_part1_folding[q={}]", q),
            per_query_part1_folding::generate_cs,
            q
        );
        run_per_query!(
            &format!("per_query_part2_num_trace[q={}]", q),
            per_query_part2_num_trace::generate_cs,
            q
        );
        run_per_query!(
            &format!("per_query_part3_num_constant[q={}]", q),
            per_query_part3_num_constant::generate_cs,
            q
        );
        run_per_query!(
            &format!("per_query_part4_num_composition[q={}]", q),
            per_query_part4_num_composition::generate_cs,
            q
        );
        run_per_query!(
            &format!("per_query_part5_num_interaction_shifted[q={}]", q),
            per_query_part5_num_interaction_shifted::generate_cs,
            q
        );
        run_per_query!(
            &format!("per_query_part6_num_interaction1[q={}]", q),
            per_query_part6_num_interaction1::generate_cs,
            q
        );
        run_per_query!(
            &format!("per_query_part7_num_interaction2[q={}]", q),
            per_query_part7_num_interaction2::generate_cs,
            q
        );
        run_per_query!(
            &format!("per_query_part8_last_step[q={}]", q),
            per_query_part8_last_step::generate_cs,
            q
        );
    }

    run_fixed!("part8_cleanup", part8_cleanup::generate_cs);

    // Print a compact per-part table
    println!();
    println!(
        "{:<50} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "part", "total", "plumbing", "hash", "push", "arith", "compare"
    );
    for (name, b) in per_part.iter() {
        println!(
            "{:<50} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
            name, b.total, b.stack_plumbing, b.hash_work, b.push_data, b.arith, b.compare
        );
    }

    println!();
    println!("{}", "=".repeat(80));
    println!("TOTAL across all 72 parts: {} bytes", total.total);
    println!(
        "  stack plumbing (picks/rolls/dups/alt) : {:>8} B  ({:>5.1}%)",
        total.stack_plumbing,
        total.stack_plumbing as f64 / total.total as f64 * 100.0
    );
    println!(
        "  hash work  (SHA256 / CAT)             : {:>8} B  ({:>5.1}%)",
        total.hash_work,
        total.hash_work as f64 / total.total as f64 * 100.0
    );
    println!(
        "  push data (constants + nums + pushes) : {:>8} B  ({:>5.1}%)",
        total.push_data,
        total.push_data as f64 / total.total as f64 * 100.0
    );
    println!(
        "  arithmetic (ADD/SUB/ABS/NEG/...)      : {:>8} B  ({:>5.1}%)",
        total.arith,
        total.arith as f64 / total.total as f64 * 100.0
    );
    println!(
        "  compare + control (EQ/VERIFY/IF/...)  : {:>8} B  ({:>5.1}%)",
        total.compare,
        total.compare as f64 / total.total as f64 * 100.0
    );
    println!(
        "  other                                 : {:>8} B  ({:>5.1}%)",
        total.other,
        total.other as f64 / total.total as f64 * 100.0
    );

    println!();
    println!("Top individual opcodes:");
    println!(
        "  OP_SHA256        : {:>8}    ({:>6.1} KB at 1 byte each)",
        total.op_sha256,
        total.op_sha256 as f64 / 1024.0
    );
    println!(
        "  OP_CAT           : {:>8}    ({:>6.1} KB at 1 byte each)",
        total.op_cat,
        total.op_cat as f64 / 1024.0
    );
    println!("  OP_PICK          : {:>8}", total.op_pick);
    println!("  OP_ROLL          : {:>8}", total.op_roll);
    println!("  OP_DUP           : {:>8}", total.op_dup);
    println!("  OP_TOALTSTACK    : {:>8}", total.op_toaltstack);
    println!("  OP_FROMALTSTACK  : {:>8}", total.op_fromaltstack);
    println!("  OP_EQUALVERIFY   : {:>8}", total.op_equalverify);
    println!("  OP_ADD           : {:>8}", total.op_add);
    println!("  OP_SUB           : {:>8}", total.op_sub);
    println!(
        "  OP_MUL           : {:>8}    (op-mulmod only)",
        total.op_mul
    );
    println!(
        "  OP_MOD           : {:>8}    (op-mulmod only)",
        total.op_mod
    );
}
