use crate::dsl::primitives::m31::M31Var;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use crate::treepp::*;
use anyhow::Result;
use bitcoin_script_dsl::bvar::{AllocVar, BVar};
use bitcoin_script_dsl::options::Options;
use bitcoin_script_dsl::stack::Stack;
use stwo_prover::core::fields::m31::M31;

pub fn ibutterfly(
    table: &TableVar,
    v0: &QM31Var,
    v1: &QM31Var,
    itwid: &M31Var,
) -> (QM31Var, QM31Var) {
    let new_v0 = v0 + v1;

    let diff = v0 - v1;
    let new_v1 = &diff * (table, itwid);

    (new_v0, new_v1)
}

pub fn decompose_positions(pos: &M31Var, n: usize) -> Vec<M31Var> {
    let cs = pos.cs();

    let mut hints = vec![];
    let mut res = vec![];

    let mut cur = pos.value.0;

    for _ in 0..n {
        hints.push(cur & 1);
        cur >>= 1;
        res.push(cur);
    }
    hints.push(cur);

    let mut hint_vars = vec![];
    for &hint in hints.iter() {
        hint_vars.push(M31Var::new_hint(&cs, M31::from(hint)).unwrap());
    }

    let mut variables = vec![];
    variables.push(pos.variable);
    for hint_var in hint_vars.iter() {
        variables.push(hint_var.variable);
    }

    cs.insert_script_complex(
        decompose_positions_gadget,
        variables,
        &Options::new().with_u32("n", n as u32),
    )
    .unwrap();

    let mut res_vars = vec![];
    for &elem in res.iter() {
        res_vars.push(M31Var::new_function_output(&cs, M31::from(elem)).unwrap());
    }

    res_vars
}

pub fn skip_one_and_extract_bits(pos: &M31Var, n: usize) -> Vec<M31Var> {
    let cs = pos.cs();

    let mut hints = vec![];
    let mut cur = pos.value.0;

    for _ in 0..n {
        hints.push(cur & 1);
        cur >>= 1;
    }
    hints.push(cur & 1);
    cur >>= 1;
    hints.push(cur);

    let mut hint_vars = vec![];
    for &hint in hints.iter() {
        hint_vars.push(M31Var::new_hint(&cs, M31::from(hint)).unwrap());
    }

    let mut variables = vec![];
    variables.push(pos.variable);
    for hint_var in hint_vars.iter() {
        variables.push(hint_var.variable);
    }

    cs.insert_script_complex(
        skip_one_and_extract_bits_gadget,
        variables,
        &Options::new().with_u32("n", n as u32),
    )
    .unwrap();

    hint_vars[1..=n].to_vec()
}

fn decompose_positions_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let n = options.get_u32("n")?;

    Ok(script! {
        // stack:
        // - pos
        // - bit hints
        // - remainder hint

        OP_DUP OP_TOALTSTACK

        for _ in 0..n - 1 {
            OP_DUP OP_ADD OP_SWAP check_0_or_1 OP_ADD OP_DUP OP_TOALTSTACK
        }

        OP_DUP OP_ADD OP_SWAP check_0_or_1 OP_ADD
        OP_EQUALVERIFY

        for _ in 0..n {
            OP_FROMALTSTACK
        }
    })
}

fn skip_one_and_extract_bits_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let n = options.get_u32("n")?;

    Ok(script! {
        // stack:
        // - pos
        // - n+1 bits
        // - remainder

        for _ in 0..(n + 1) {
            OP_DUP OP_ADD
            OP_SWAP check_0_or_1 OP_ADD
        }

        OP_EQUALVERIFY
    })
}

fn check_0_or_1() -> Script {
    script! {
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
        OP_DUP 1 OP_LESSTHANOREQUAL OP_VERIFY
    }
}

#[cfg(test)]
mod test {
    use crate::algorithms::folding::{decompose_positions, skip_one_and_extract_bits};
    use crate::dsl::primitives::m31::M31Var;
    use crate::treepp::*;
    use bitcoin_script_dsl::bvar::AllocVar;
    use bitcoin_script_dsl::constraint_system::ConstraintSystem;
    use bitcoin_script_dsl::test_program;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use stwo_prover::core::fields::m31::M31;

    #[test]
    fn test_decompose_positions() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let num = prng.gen_range(0..=1023);

        let expected = [num >> 1, num >> 2, num >> 3, num >> 4, num >> 5];

        let cs = ConstraintSystem::new_ref();
        let num_var = M31Var::new_program_input(&cs, M31::from(num)).unwrap();

        let all_pos = decompose_positions(&num_var, 5);

        for pos in all_pos.iter() {
            cs.set_program_output(pos).unwrap();
        }

        test_program(
            cs,
            script! {
                for elem in expected.iter() {
                    { *elem }
                }
            },
        )
        .unwrap()
    }

    #[test]
    fn test_skip_one_and_extract_bits() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let cs = ConstraintSystem::new_ref();

            let test_position = prng.gen_range(0..=1023);

            let test_position_var =
                M31Var::new_program_input(&cs, M31::from(test_position)).unwrap();
            let bits_vars = skip_one_and_extract_bits(&test_position_var, 5);

            let expected = [
                (test_position >> 1) & 1,
                (test_position >> 2) & 1,
                (test_position >> 3) & 1,
                (test_position >> 4) & 1,
                (test_position >> 5) & 1,
            ];

            for bit_var in bits_vars.iter() {
                cs.set_program_output(bit_var).unwrap();
            }

            test_program(
                cs,
                script! {
                    { expected.to_vec() }
                },
            )
            .unwrap()
        }
    }
}
