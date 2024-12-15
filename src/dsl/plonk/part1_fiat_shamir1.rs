use crate::algorithms::point::get_oods_point;
use crate::algorithms::pow::verify_pow;
use crate::algorithms::twin_tree::query_and_verify_merkle_twin_tree;
use crate::dsl::plonk::hints::{Hints, LOG_N_ROWS};
use crate::dsl::primitives::channel::HashVarWithChannel;
use crate::dsl::primitives::cm31::CM31Var;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use anyhow::Result;
use bitcoin_script_dsl::builtins::hash::HashVar;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::ldm::LDM;
use stwo_prover::core::channel::Sha256Channel;
use stwo_prover::core::prover::{LOG_BLOWUP_FACTOR, PROOF_OF_WORK_BITS};

pub fn generate_cs(hints: &Hints, ldm: &mut LDM) -> Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    ldm.init(&cs)?;

    let channel = &mut Sha256Channel::default();

    // Step 1: mix the channel with the trace commitment
    let mut channel_var = HashVar::new_constant(&cs, channel.digest().as_ref().to_vec())?;
    let trace_commitment_var = HashVar::new_hint(
        &cs,
        hints.fiat_shamir_hints.commitments[0].as_ref().to_vec(),
    )?;

    channel_var = &channel_var + &trace_commitment_var;

    // Step 2: derive the z and alpha
    let z_var = channel_var.draw_felt();
    ldm.write("z", &z_var)?;

    let alpha_var = channel_var.draw_felt();
    ldm.write("alpha", &alpha_var)?;

    // Step 3: mix the channel with the interaction commitment and constant commitment
    let interaction_commitment_var = HashVar::new_hint(
        &cs,
        hints.fiat_shamir_hints.commitments[1].as_ref().to_vec(),
    )?;
    let constant_commitment_var = HashVar::new_hint(
        &cs,
        hints.fiat_shamir_hints.commitments[2].as_ref().to_vec(),
    )?;

    channel_var = &channel_var + &interaction_commitment_var;
    channel_var = &channel_var + &constant_commitment_var;

    let composition_fold_random_coeff_var = channel_var.draw_felt();
    ldm.write(
        "composition_fold_random_coeff",
        &composition_fold_random_coeff_var,
    )?;

    // Step 4: mix the channel with composition commitment
    let composition_commitment_var = HashVar::new_hint(
        &cs,
        hints.fiat_shamir_hints.commitments[3].as_ref().to_vec(),
    )?;
    ldm.write("composition_commitment", &composition_commitment_var)?;
    channel_var = &channel_var + &composition_commitment_var;

    // Step 5: save a copy of the channel before drawing the OODS point draw (for deferred computation)
    let mut channel_var_before_oods = channel_var.clone();
    let _ = channel_var.draw_felt();

    // Step 6: mix the channel with the trace, interaction, constant, composition values
    let mut trace_oods_values_vars = vec![];
    assert_eq!(hints.fiat_shamir_hints.trace_oods_values.len(), 4);
    for &trace_oods_value in hints.fiat_shamir_hints.trace_oods_values.iter() {
        trace_oods_values_vars.push(QM31Var::new_hint(&cs, trace_oods_value)?);
    }

    let mut interaction_oods_values_vars = vec![];
    assert_eq!(hints.fiat_shamir_hints.interaction_oods_values.len(), 12);
    for &interaction_oods_value in hints.fiat_shamir_hints.interaction_oods_values.iter() {
        interaction_oods_values_vars.push(QM31Var::new_hint(&cs, interaction_oods_value)?);
    }

    let mut constant_oods_values_vars = vec![];
    assert_eq!(hints.fiat_shamir_hints.constant_oods_values.len(), 4);
    for &constant_oods_value in hints.fiat_shamir_hints.constant_oods_values.iter() {
        constant_oods_values_vars.push(QM31Var::new_hint(&cs, constant_oods_value)?);
    }

    let mut composition_oods_raw_values_vars = vec![];
    assert_eq!(hints.fiat_shamir_hints.constant_oods_values.len(), 4);
    for &composition_oods_raw_value in hints.fiat_shamir_hints.composition_oods_values.iter() {
        composition_oods_raw_values_vars.push(QM31Var::new_hint(&cs, composition_oods_raw_value)?);
    }

    for (i, trace_oods_value_var) in trace_oods_values_vars.iter().enumerate() {
        channel_var = &channel_var + trace_oods_value_var;
        ldm.write(format!("trace_oods_value_{}", i), trace_oods_value_var)?;
    }
    for (i, interaction_oods_value_var) in interaction_oods_values_vars.iter().enumerate() {
        channel_var = &channel_var + interaction_oods_value_var;
        ldm.write(
            format!("interaction_oods_value_{}", i),
            interaction_oods_value_var,
        )?;
    }
    for (i, constant_oods_value_var) in constant_oods_values_vars.iter().enumerate() {
        channel_var = &channel_var + constant_oods_value_var;
        ldm.write(
            format!("constant_oods_value_{}", i),
            constant_oods_value_var,
        )?;
    }
    for (i, composition_oods_raw_value_var) in composition_oods_raw_values_vars.iter().enumerate() {
        channel_var = &channel_var + composition_oods_raw_value_var;
        ldm.write(
            format!("composition_oods_value_{}", i),
            composition_oods_raw_value_var,
        )?;
    }

    // Step 7: derive line_batch_random_coeff and fri_fold_random_coeff
    let line_batch_random_coeff_var = channel_var.draw_felt();
    ldm.write("line_batch_random_coeff", &line_batch_random_coeff_var)?;
    let fri_fold_random_coeff_var = channel_var.draw_felt();
    ldm.write("fri_fold_random_coeff", &fri_fold_random_coeff_var)?;

    // Step 8: get the FRI trees' commitments, mix them with the channel one by one, and obtain the folding alphas
    let mut fri_tree_commitments_vars = vec![];
    let mut folding_alphas_vars = vec![];
    for (i, fri_tree_commitment) in hints
        .fiat_shamir_hints
        .fri_layer_commitments
        .iter()
        .enumerate()
    {
        let fri_tree_commitment_var =
            HashVar::new_hint(&cs, fri_tree_commitment.as_ref().to_vec())?;
        ldm.write(
            format!("fri_tree_commitments_{}", i),
            &fri_tree_commitment_var,
        )?;

        channel_var = &channel_var + &fri_tree_commitment_var;
        fri_tree_commitments_vars.push(fri_tree_commitment_var);

        let folding_alpha_var = channel_var.draw_felt();
        ldm.write(format!("folding_alpha_{}", i), &folding_alpha_var)?;
        folding_alphas_vars.push(folding_alpha_var);
    }

    // Step 9: get the last layer and mix it with the channel
    let last_layer_var = QM31Var::new_hint(&cs, hints.fiat_shamir_hints.last_layer)?;
    ldm.write("last_layer", &last_layer_var)?;
    channel_var = &channel_var + &last_layer_var;

    // Step 10: check proof of work
    verify_pow(
        &mut channel_var,
        PROOF_OF_WORK_BITS,
        hints.fiat_shamir_hints.pow_hint.nonce,
    )?;

    // Step 11: draw all the queries
    let queries = channel_var.draw_numbers(8, (LOG_N_ROWS + LOG_BLOWUP_FACTOR + 1) as usize);
    for (i, query) in queries.iter().enumerate() {
        ldm.write(format!("query_{}", i), query)?;
    }
    // at this moment, the channel is no longer needed.

    // Step 12: query the trace commitment on the queries
    for (i, (query, proof)) in queries
        .iter()
        .zip(hints.fiat_shamir_hints.merkle_proofs_traces.iter())
        .enumerate()
    {
        let res = query_and_verify_merkle_twin_tree(&trace_commitment_var, query, proof)?;
        ldm.write(format!("trace_mult_queried_results_{}_l", i), &res.0[0])?;
        ldm.write(format!("trace_mult_queried_results_{}_r", i), &res.1[0])?;
        ldm.write(format!("trace_a_val_queried_results_{}_l", i), &res.0[1])?;
        ldm.write(format!("trace_a_val_queried_results_{}_r", i), &res.1[1])?;
        ldm.write(format!("trace_b_val_queried_results_{}_l", i), &res.0[2])?;
        ldm.write(format!("trace_b_val_queried_results_{}_r", i), &res.1[2])?;
        ldm.write(format!("trace_c_val_queried_results_{}_l", i), &res.0[3])?;
        ldm.write(format!("trace_c_val_queried_results_{}_r", i), &res.1[3])?;
    }

    // Step 13: query the interaction commitment on the queries
    for (i, (query, proof)) in queries
        .iter()
        .zip(hints.fiat_shamir_hints.merkle_proofs_interactions.iter())
        .enumerate()
    {
        let res = query_and_verify_merkle_twin_tree(&interaction_commitment_var, query, proof)?;

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
        ldm.write(format!("interaction_ab_queried_results_{}_l", i), &left)?;
        ldm.write(format!("interaction_ab_queried_results_{}_r", i), &right)?;

        let left = QM31Var {
            first: CM31Var {
                real: res.0[4].clone(),
                imag: res.0[5].clone(),
            },
            second: CM31Var {
                real: res.0[6].clone(),
                imag: res.0[7].clone(),
            },
        };
        let right = QM31Var {
            first: CM31Var {
                real: res.1[4].clone(),
                imag: res.1[5].clone(),
            },
            second: CM31Var {
                real: res.1[6].clone(),
                imag: res.1[7].clone(),
            },
        };
        ldm.write(format!("interaction_cum_queried_results_{}_l", i), &left)?;
        ldm.write(format!("interaction_cum_queried_results_{}_r", i), &right)?;
    }

    // Step 14: query the constant commitment on the queries
    for (i, (query, proof)) in queries
        .iter()
        .zip(hints.fiat_shamir_hints.merkle_proofs_constants.iter())
        .enumerate()
    {
        let res = query_and_verify_merkle_twin_tree(&constant_commitment_var, query, proof)?;
        ldm.write(
            format!("constant_a_wire_queried_results_{}_l", i),
            &res.0[0],
        )?;
        ldm.write(
            format!("constant_a_wire_queried_results_{}_r", i),
            &res.1[0],
        )?;
        ldm.write(
            format!("constant_b_wire_queried_results_{}_l", i),
            &res.0[1],
        )?;
        ldm.write(
            format!("constant_b_wire_queried_results_{}_r", i),
            &res.1[1],
        )?;
        ldm.write(
            format!("constant_c_wire_queried_results_{}_l", i),
            &res.0[2],
        )?;
        ldm.write(
            format!("constant_c_wire_queried_results_{}_r", i),
            &res.1[2],
        )?;
        ldm.write(format!("constant_op_queried_results_{}_l", i), &res.0[3])?;
        ldm.write(format!("constant_op_queried_results_{}_r", i), &res.1[3])?;
    }

    // compute the OODS point
    let table = TableVar::new_constant(&cs, ())?;
    let point = get_oods_point(&mut channel_var_before_oods, &table);
    ldm.write("oods_x", &point.x)?;
    ldm.write("oods_y", &point.y)?;

    ldm.save()?;

    Ok(cs)
}
