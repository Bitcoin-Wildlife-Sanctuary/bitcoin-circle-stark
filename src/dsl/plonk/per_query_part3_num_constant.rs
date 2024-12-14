use crate::algorithms::quotient::{apply_twin, denominator_inverse_from_prepared};
use crate::dsl::plonk::hints::Hints;
use crate::dsl::primitives::cm31::CM31Var;
use crate::dsl::primitives::m31::M31Var;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::ldm::LDM;

pub fn generate_cs(
    _: &Hints,
    ldm: &mut LDM,
    query_idx: usize,
) -> anyhow::Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    ldm.init(&cs)?;

    let x: M31Var = ldm.read(format!("circle_point_x_{}", query_idx))?;
    let y: M31Var = ldm.read(format!("circle_point_y_{}", query_idx))?;
    let table = TableVar::new_constant(&cs, ())?;

    let mut constant_queried_results = Vec::<(M31Var, M31Var)>::new();
    constant_queried_results.push((
        ldm.read(format!("constant_a_wire_queried_results_{}_l", query_idx))?,
        ldm.read(format!("constant_a_wire_queried_results_{}_r", query_idx))?,
    ));
    constant_queried_results.push((
        ldm.read(format!("constant_b_wire_queried_results_{}_l", query_idx))?,
        ldm.read(format!("constant_b_wire_queried_results_{}_r", query_idx))?,
    ));
    constant_queried_results.push((
        ldm.read(format!("constant_c_wire_queried_results_{}_l", query_idx))?,
        ldm.read(format!("constant_c_wire_queried_results_{}_r", query_idx))?,
    ));
    constant_queried_results.push((
        ldm.read(format!("constant_op_queried_results_{}_l", query_idx))?,
        ldm.read(format!("constant_op_queried_results_{}_r", query_idx))?,
    ));

    let mut column_line_constant_vars = Vec::<(CM31Var, CM31Var)>::new();
    for i in 0..4 {
        column_line_constant_vars.push((
            ldm.read(format!("column_line_coeffs_constant_{}_a", i))?,
            ldm.read(format!("column_line_coeffs_constant_{}_b", i))?,
        ))
    }

    let numerator_constant_a_wire = apply_twin(
        &table,
        &y,
        &constant_queried_results[0].0,
        &constant_queried_results[0].1,
        &column_line_constant_vars[0].0,
        &column_line_constant_vars[0].1,
    );

    let numerator_constant_b_wire = apply_twin(
        &table,
        &y,
        &constant_queried_results[1].0,
        &constant_queried_results[1].1,
        &column_line_constant_vars[1].0,
        &column_line_constant_vars[1].1,
    );

    let numerator_constant_c_wire = apply_twin(
        &table,
        &y,
        &constant_queried_results[2].0,
        &constant_queried_results[2].1,
        &column_line_constant_vars[2].0,
        &column_line_constant_vars[2].1,
    );

    let numerator_constant_op = apply_twin(
        &table,
        &y,
        &constant_queried_results[3].0,
        &constant_queried_results[3].1,
        &column_line_constant_vars[3].0,
        &column_line_constant_vars[3].1,
    );

    let alpha3: QM31Var = ldm.read("line_batch_random_coeff_3")?;
    let alpha2: QM31Var = ldm.read("line_batch_random_coeff_2")?;
    let alpha: QM31Var = ldm.read("line_batch_random_coeff")?;

    let mut sum_num_constant_l = &alpha3 * (&table, &numerator_constant_a_wire.0);
    sum_num_constant_l = &sum_num_constant_l + &(&alpha2 * (&table, &numerator_constant_b_wire.0));
    sum_num_constant_l = &sum_num_constant_l + &(&alpha * (&table, &numerator_constant_c_wire.0));
    sum_num_constant_l = &sum_num_constant_l + &numerator_constant_op.0;

    let mut sum_num_constant_r = &alpha3 * (&table, &numerator_constant_a_wire.1);
    sum_num_constant_r = &sum_num_constant_r + &(&alpha2 * (&table, &numerator_constant_b_wire.1));
    sum_num_constant_r = &sum_num_constant_r + &(&alpha * (&table, &numerator_constant_c_wire.1));
    sum_num_constant_r = &sum_num_constant_r + &numerator_constant_op.1;

    let alpha8: QM31Var = ldm.read("line_batch_random_coeff_8")?;

    let alpha8constant_l = &alpha8 * (&table, &sum_num_constant_l);
    let alpha8constant_r = &alpha8 * (&table, &sum_num_constant_r);

    ldm.write(format!("alpha8constant_{}_l", query_idx), &alpha8constant_l)?;
    ldm.write(format!("alpha8constant_{}_r", query_idx), &alpha8constant_r)?;

    let prepared_oods_shifted_by_1_a: CM31Var = ldm.read("prepared_oods_shifted_by_1_a")?;
    let prepared_oods_shifted_by_1_b: CM31Var = ldm.read("prepared_oods_shifted_by_1_b")?;

    let denominator_inverse_var = denominator_inverse_from_prepared(
        &table,
        &prepared_oods_shifted_by_1_a,
        &prepared_oods_shifted_by_1_b,
        &x,
        &y,
    );
    ldm.write(
        format!("denominator_inverse_shifted_{}_l", query_idx),
        &denominator_inverse_var.0,
    )?;
    ldm.write(
        format!("denominator_inverse_shifted_{}_r", query_idx),
        &denominator_inverse_var.1,
    )?;

    ldm.save()?;
    Ok(cs)
}
