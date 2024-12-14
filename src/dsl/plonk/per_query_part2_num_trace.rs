use crate::algorithms::quotient::{apply_twin, denominator_inverse_from_prepared};
use crate::dsl::plonk::hints::Hints;
use crate::dsl::primitives::cm31::CM31Var;
use crate::dsl::primitives::m31::M31Var;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use anyhow::Result;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::ldm::LDM;

pub fn generate_cs(_: &Hints, ldm: &mut LDM, query_idx: usize) -> Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    ldm.init(&cs)?;

    let x: M31Var = ldm.read(format!("circle_point_x_{}", query_idx))?;
    let y: M31Var = ldm.read(format!("circle_point_y_{}", query_idx))?;
    let table = TableVar::new_constant(&cs, ())?;

    let mut trace_queried_results = Vec::<(M31Var, M31Var)>::new();
    trace_queried_results.push((
        ldm.read(format!("trace_mult_queried_results_{}_l", query_idx))?,
        ldm.read(format!("trace_mult_queried_results_{}_r", query_idx))?,
    ));
    trace_queried_results.push((
        ldm.read(format!("trace_a_val_queried_results_{}_l", query_idx))?,
        ldm.read(format!("trace_a_val_queried_results_{}_r", query_idx))?,
    ));
    trace_queried_results.push((
        ldm.read(format!("trace_b_val_queried_results_{}_l", query_idx))?,
        ldm.read(format!("trace_b_val_queried_results_{}_r", query_idx))?,
    ));
    trace_queried_results.push((
        ldm.read(format!("trace_c_val_queried_results_{}_l", query_idx))?,
        ldm.read(format!("trace_c_val_queried_results_{}_r", query_idx))?,
    ));

    let mut column_line_trace_vars = Vec::<(CM31Var, CM31Var)>::new();
    for i in 0..4 {
        column_line_trace_vars.push((
            ldm.read(format!("column_line_coeffs_trace_{}_a", i))?,
            ldm.read(format!("column_line_coeffs_trace_{}_b", i))?,
        ))
    }

    let numerator_trace_mult = apply_twin(
        &table,
        &y,
        &trace_queried_results[0].0,
        &trace_queried_results[0].1,
        &column_line_trace_vars[0].0,
        &column_line_trace_vars[0].1,
    );

    let numerator_trace_a_val = apply_twin(
        &table,
        &y,
        &trace_queried_results[1].0,
        &trace_queried_results[1].1,
        &column_line_trace_vars[1].0,
        &column_line_trace_vars[1].1,
    );

    let numerator_trace_b_val = apply_twin(
        &table,
        &y,
        &trace_queried_results[2].0,
        &trace_queried_results[2].1,
        &column_line_trace_vars[2].0,
        &column_line_trace_vars[2].1,
    );

    let numerator_trace_c_val = apply_twin(
        &table,
        &y,
        &trace_queried_results[3].0,
        &trace_queried_results[3].1,
        &column_line_trace_vars[3].0,
        &column_line_trace_vars[3].1,
    );

    let alpha3: QM31Var = ldm.read("line_batch_random_coeff_3")?;
    let alpha2: QM31Var = ldm.read("line_batch_random_coeff_2")?;
    let alpha: QM31Var = ldm.read("line_batch_random_coeff")?;

    let mut sum_num_trace_l = &alpha3 * (&table, &numerator_trace_mult.0);
    sum_num_trace_l = &sum_num_trace_l + &(&alpha2 * (&table, &numerator_trace_a_val.0));
    sum_num_trace_l = &sum_num_trace_l + &(&alpha * (&table, &numerator_trace_b_val.0));
    sum_num_trace_l = &sum_num_trace_l + &numerator_trace_c_val.0;

    let mut sum_num_trace_r = &alpha3 * (&table, &numerator_trace_mult.1);
    sum_num_trace_r = &sum_num_trace_r + &(&alpha2 * (&table, &numerator_trace_a_val.1));
    sum_num_trace_r = &sum_num_trace_r + &(&alpha * (&table, &numerator_trace_b_val.1));
    sum_num_trace_r = &sum_num_trace_r + &numerator_trace_c_val.1;

    let alpha20: QM31Var = ldm.read("line_batch_random_coeff_20")?;

    let alpha20trace_l = &alpha20 * (&table, &sum_num_trace_l);
    let alpha20trace_r = &alpha20 * (&table, &sum_num_trace_r);

    ldm.write(format!("alpha20trace_{}_l", query_idx), &alpha20trace_l)?;
    ldm.write(format!("alpha20trace_{}_r", query_idx), &alpha20trace_r)?;

    let prepared_oods_a: CM31Var = ldm.read("prepared_oods_a")?;
    let prepared_oods_b: CM31Var = ldm.read("prepared_oods_b")?;

    let denominator_inverse_var =
        denominator_inverse_from_prepared(&table, &prepared_oods_a, &prepared_oods_b, &x, &y);
    ldm.write(
        format!("denominator_inverse_{}_l", query_idx),
        &denominator_inverse_var.0,
    )?;
    ldm.write(
        format!("denominator_inverse_{}_r", query_idx),
        &denominator_inverse_var.1,
    )?;

    ldm.save()?;
    Ok(cs)
}
