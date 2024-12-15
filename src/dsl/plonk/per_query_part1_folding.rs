use crate::algorithms::folding::{decompose_positions, ibutterfly, skip_one_and_extract_bits};
use crate::algorithms::twin_tree::query_and_verify_merkle_twin_tree;
use crate::dsl::plonk::hints::{Hints, LOG_N_ROWS};
use crate::dsl::primitives::cm31::CM31Var;
use crate::dsl::primitives::m31::M31Var;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use anyhow::Result;
use bitcoin_script_dsl::builtins::hash::HashVar;
use bitcoin_script_dsl::bvar::{AllocVar, BVar};
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::ldm::LDM;

pub fn generate_cs(hints: &Hints, ldm: &mut LDM, query_idx: usize) -> Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    ldm.init(&cs)?;

    let query: M31Var = ldm.read(format!("query_{}", query_idx))?;
    let queries = decompose_positions(&query, 5);

    let mut fri_tree_commitments_vars = Vec::<HashVar>::new();
    for i in 0..LOG_N_ROWS {
        fri_tree_commitments_vars.push(ldm.read(format!("fri_tree_commitments_{}", i))?);
    }

    let mut folding_intermediate_vars = vec![];
    for ((commitment, proof), cur_query) in fri_tree_commitments_vars
        .iter()
        .zip(hints.per_query_fold_hints[query_idx].twin_proofs.iter())
        .zip(queries.iter())
    {
        let res = query_and_verify_merkle_twin_tree(commitment, cur_query, proof)?;

        let left = QM31Var {
            first: CM31Var {
                real: res.0[0].clone(),
                imag: res.0[1].clone(),
            },
            second: CM31Var {
                real: res.0[2].clone(),
                imag: res.0[3].clone(),
            },
        };
        let right = QM31Var {
            first: CM31Var {
                real: res.1[0].clone(),
                imag: res.1[1].clone(),
            },
            second: CM31Var {
                real: res.1[2].clone(),
                imag: res.1[3].clone(),
            },
        };

        folding_intermediate_vars.push((left, right));
    }

    let swap_bits_vars = skip_one_and_extract_bits(&query, 5);

    let mut twiddles_vars = Vec::<M31Var>::new();
    twiddles_vars.push(ldm.read(format!("twiddle_factor_1_{}", query_idx))?);
    twiddles_vars.push(ldm.read(format!("twiddle_factor_2_{}", query_idx))?);
    twiddles_vars.push(ldm.read(format!("twiddle_factor_3_{}", query_idx))?);
    twiddles_vars.push(ldm.read(format!("twiddle_factor_4_{}", query_idx))?);
    twiddles_vars.push(ldm.read(format!("twiddle_factor_5_{}", query_idx))?);

    let mut folding_alphas_vars = Vec::<QM31Var>::new();
    for i in 0..LOG_N_ROWS {
        folding_alphas_vars.push(ldm.read(format!("folding_alpha_{}", i))?);
    }

    let table = TableVar::new_constant(&cs, ())?;

    let mut folded_results_vars = vec![];
    for ((folding_intermediate_result, twiddle_var), folding_alpha_var) in folding_intermediate_vars
        .iter()
        .zip(twiddles_vars.iter())
        .zip(folding_alphas_vars.iter())
    {
        let ifft_results_vars = ibutterfly(
            &table,
            &folding_intermediate_result.0,
            &folding_intermediate_result.1,
            twiddle_var,
        );

        folded_results_vars
            .push(&ifft_results_vars.0 + &(&ifft_results_vars.1 * (&table, folding_alpha_var)));
    }

    for i in 0..4 {
        let swapped_result = folding_intermediate_vars[i + 1]
            .0
            .conditional_swap(&folding_intermediate_vars[i + 1].1, &swap_bits_vars[i + 1])
            .0;
        swapped_result.equalverify(&folded_results_vars[i])?;
    }

    let expected_entry_quotient = folding_intermediate_vars[0]
        .0
        .conditional_swap(&folding_intermediate_vars[0].1, &swap_bits_vars[0])
        .0;
    ldm.write(
        format!("expected_entry_quotient_{}", query_idx),
        &expected_entry_quotient,
    )?;

    let last_layer_var: QM31Var = ldm.read("last_layer")?;
    folded_results_vars[4].equalverify(&last_layer_var)?;

    ldm.save()?;
    Ok(cs)
}
