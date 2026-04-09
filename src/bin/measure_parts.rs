//! Compile every part of the Plonk verifier pipeline and print the raw
//! compiled-script length in bytes, so we have ground truth to compare
//! against the fee table in `dsl/plonk/covenant.rs`.

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

fn main() {
    let hints = Hints::instance();
    let mut ldm = LDM::new();

    let mut total_script: usize = 0;
    let mut report = |name: &str, bytes: usize| {
        println!("{:<50} {:>8} bytes", name, bytes);
        total_script += bytes;
    };

    macro_rules! run_fixed {
        ($name:expr, $f:path) => {{
            let cs = $f(&hints, &mut ldm).unwrap();
            let program = Compiler::compile(cs).unwrap();
            report($name, program.script.len());
        }};
    }
    macro_rules! run_per_query {
        ($name:expr, $f:path, $q:expr) => {{
            let cs = $f(&hints, &mut ldm, $q).unwrap();
            let program = Compiler::compile(cs).unwrap();
            report($name, program.script.len());
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

    println!("-----");
    println!("{:<50} {:>8} bytes", "TOTAL", total_script);
}
