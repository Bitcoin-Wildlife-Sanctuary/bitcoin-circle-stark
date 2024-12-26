use crate::algorithms::precomputed_tree::query_and_verify_precomputed_merkle_tree;
use crate::algorithms::twin_tree::query_and_verify_merkle_twin_tree;
use crate::dsl::plonk::hints::Hints;
use crate::dsl::primitives::cm31::CM31Var;
use crate::dsl::primitives::m31::M31Var;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use crate::precomputed_merkle_tree::{
    get_precomputed_merkle_tree_roots, PRECOMPUTED_MERKLE_TREE_ROOTS,
};
use anyhow::Result;
use bitcoin_script_dsl::builtins::hash::HashVar;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::ldm::LDM;
use stwo_prover::core::prover::N_QUERIES;

pub fn generate_cs(hints: &Hints, ldm: &mut LDM) -> Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    ldm.init(&cs)?;

    let composition_commitment_var: HashVar = ldm.read("composition_commitment")?;

    let mut queries = Vec::<M31Var>::new();
    for i in 0..N_QUERIES {
        queries.push(ldm.read(format!("query_{}", i))?)
    }

    // Step 1: query the composition commitment on the queries
    for (i, (query, proof)) in queries
        .iter()
        .zip(hints.fiat_shamir_hints.merkle_proofs_compositions.iter())
        .enumerate()
    {
        let res = query_and_verify_merkle_twin_tree(&composition_commitment_var, query, proof)?;

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
        ldm.write(format!("composition_queried_results_{}_l", i), &left)?;
        ldm.write(format!("composition_queried_results_{}_r", i), &right)?;
    }

    let precomputed_merkle_tree_roots =
        PRECOMPUTED_MERKLE_TREE_ROOTS.get_or_init(get_precomputed_merkle_tree_roots);

    for (i, (query, pre_query_quotients_hint)) in queries
        .iter()
        .zip(hints.per_query_quotients_hints.iter())
        .enumerate()
    {
        let proof = &pre_query_quotients_hint.precomputed_merkle_proofs[0];
        let res = query_and_verify_precomputed_merkle_tree(
            precomputed_merkle_tree_roots.get(&15).unwrap().as_ref(),
            query,
            proof,
        )?;
        ldm.write(format!("circle_point_x_{}", i), &res.circle_point_x_var)?;
        ldm.write(format!("circle_point_y_{}", i), &res.circle_point_y_var)?;
        ldm.write(format!("twiddle_factor_1_{}", i), &res.twiddles_var[13])?;
        ldm.write(format!("twiddle_factor_2_{}", i), &res.twiddles_var[12])?;
        ldm.write(format!("twiddle_factor_3_{}", i), &res.twiddles_var[11])?;
        ldm.write(format!("twiddle_factor_4_{}", i), &res.twiddles_var[10])?;
        ldm.write(format!("twiddle_factor_5_{}", i), &res.twiddles_var[9])?;
    }

    let table = TableVar::new_constant(&cs, ())?;

    let a_val_var: QM31Var = ldm.read("trace_oods_value_1")?;
    let b_val_var: QM31Var = ldm.read("trace_oods_value_2")?;
    let c_val_var: QM31Var = ldm.read("trace_oods_value_3")?;
    let op_var: QM31Var = ldm.read("constant_oods_value_3")?;

    let a_val_times_b_val = &a_val_var * (&table, &b_val_var);

    let mut res1 = &c_val_var
        - (&(&(&op_var * (&table, &(&(&a_val_var + &b_val_var) - &a_val_times_b_val)))
            + &a_val_times_b_val));

    let composition_fold_random_coeff_var: QM31Var = ldm.read("composition_fold_random_coeff")?;
    let composition_fold_random_coeff_squared_var =
        &composition_fold_random_coeff_var * &composition_fold_random_coeff_var;

    res1 = &res1 * &composition_fold_random_coeff_squared_var;

    let a_wire_var: QM31Var = ldm.read("constant_oods_value_0")?;
    let b_wire_var: QM31Var = ldm.read("constant_oods_value_1")?;
    let c_wire_var: QM31Var = ldm.read("constant_oods_value_2")?;
    let alpha_var: QM31Var = ldm.read("alpha")?;
    let z_var: QM31Var = ldm.read("z")?;

    let denominator_1_var = &(&a_wire_var + &(&alpha_var * (&table, &a_val_var))) - &z_var;
    let denominator_2_var = &(&b_wire_var + &(&alpha_var * (&table, &b_val_var))) - &z_var;

    let num_aggregated_var = &denominator_1_var + &denominator_2_var;
    let denom_aggregated_var = &denominator_1_var * (&table, &denominator_2_var);

    let a_b_logup_0_var: QM31Var = ldm.read("interaction_oods_value_0")?;
    let a_b_logup_1_var: QM31Var = ldm.read("interaction_oods_value_1")?;
    let a_b_logup_2_var: QM31Var = ldm.read("interaction_oods_value_2")?;
    let a_b_logup_3_var: QM31Var = ldm.read("interaction_oods_value_3")?;

    let mut a_b_logup_var = &a_b_logup_0_var + &a_b_logup_1_var.shift_by_i();
    a_b_logup_var = &a_b_logup_var + &a_b_logup_2_var.shift_by_j();
    a_b_logup_var = &a_b_logup_var + &a_b_logup_3_var.shift_by_ij();

    let mut res2 = &(&a_b_logup_var * (&table, &denom_aggregated_var)) - &num_aggregated_var;
    res2 = &res2 * &composition_fold_random_coeff_var;

    let res12 = &res1 + &res2;

    let denominator_3_var = &(&c_wire_var + &(&alpha_var * (&table, &c_val_var))) - &z_var;

    let c_logup_0_var: QM31Var = ldm.read("interaction_oods_value_4")?;
    let c_logup_1_var: QM31Var = ldm.read("interaction_oods_value_6")?;
    let c_logup_2_var: QM31Var = ldm.read("interaction_oods_value_8")?;
    let c_logup_3_var: QM31Var = ldm.read("interaction_oods_value_10")?;

    let mut c_logup_var = &c_logup_0_var + &c_logup_1_var.shift_by_i();
    c_logup_var = &c_logup_var + &c_logup_2_var.shift_by_j();
    c_logup_var = &c_logup_var + &c_logup_3_var.shift_by_ij();

    let c_logup_next_0_var: QM31Var = ldm.read("interaction_oods_value_5")?;
    let c_logup_next_1_var: QM31Var = ldm.read("interaction_oods_value_7")?;
    let c_logup_next_2_var: QM31Var = ldm.read("interaction_oods_value_9")?;
    let c_logup_next_3_var: QM31Var = ldm.read("interaction_oods_value_11")?;

    let mut c_logup_next_var = &c_logup_next_0_var + &c_logup_next_1_var.shift_by_i();
    c_logup_next_var = &c_logup_next_var + &c_logup_next_2_var.shift_by_j();
    c_logup_next_var = &c_logup_next_var + &c_logup_next_3_var.shift_by_ij();

    // for testing purposes, claimed sum divided is given as an unrestrained hint
    let claimed_sum_divided = QM31Var::new_hint(&cs, hints.fiat_shamir_hints.claimed_sum_divided)?;

    let mut res3 = &(&(&c_logup_var - &c_logup_next_var) - &a_b_logup_var) + &claimed_sum_divided;
    res3 = &res3 * (&table, &denominator_3_var);

    let mult_var: QM31Var = ldm.read("trace_oods_value_0")?;
    res3 = &res3 + &mult_var;

    let constraint_num = &res12 + &res3;
    ldm.write("constraint_num", &constraint_num)?;

    ldm.save()?;

    Ok(cs)
}
