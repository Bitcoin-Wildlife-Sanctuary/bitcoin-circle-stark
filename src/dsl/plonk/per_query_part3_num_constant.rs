use crate::algorithms::quotient::{apply_twin, denominator_inverse_from_prepared};
use crate::dsl::plonk::hints::Hints;
use bitcoin_script_dsl::builtins::cm31::CM31Var;
use bitcoin_script_dsl::builtins::m31::M31Var;
use bitcoin_script_dsl::builtins::qm31::QM31Var;
use bitcoin_script_dsl::builtins::table::TableVar;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::worm::WORMMemory;

pub fn generate_cs(
    _: &Hints,
    worm: &mut WORMMemory,
    query_idx: usize,
) -> anyhow::Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    worm.init(&cs)?;

    let x: M31Var = worm.read(format!("circle_point_x_{}", query_idx))?;
    let y: M31Var = worm.read(format!("circle_point_y_{}", query_idx))?;
    let table = TableVar::new_constant(&cs, ())?;

    let mut constant_queried_results = Vec::<(M31Var, M31Var)>::new();
    constant_queried_results.push((
        worm.read(format!("constant_a_wire_queried_results_{}_l", query_idx))?,
        worm.read(format!("constant_a_wire_queried_results_{}_r", query_idx))?,
    ));
    constant_queried_results.push((
        worm.read(format!("constant_b_wire_queried_results_{}_l", query_idx))?,
        worm.read(format!("constant_b_wire_queried_results_{}_r", query_idx))?,
    ));
    constant_queried_results.push((
        worm.read(format!("constant_c_wire_queried_results_{}_l", query_idx))?,
        worm.read(format!("constant_c_wire_queried_results_{}_r", query_idx))?,
    ));
    constant_queried_results.push((
        worm.read(format!("constant_op_queried_results_{}_l", query_idx))?,
        worm.read(format!("constant_op_queried_results_{}_r", query_idx))?,
    ));

    let mut column_line_constant_vars = Vec::<(CM31Var, CM31Var)>::new();
    for i in 0..4 {
        column_line_constant_vars.push((
            worm.read(format!("column_line_coeffs_constant_{}_a", i))?,
            worm.read(format!("column_line_coeffs_constant_{}_b", i))?,
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

    let alpha3: QM31Var = worm.read("line_batch_random_coeff_3")?;
    let alpha2: QM31Var = worm.read("line_batch_random_coeff_2")?;
    let alpha: QM31Var = worm.read("line_batch_random_coeff")?;

    let mut sum_num_constant_l = &alpha3 * (&table, &numerator_constant_a_wire.0);
    sum_num_constant_l = &sum_num_constant_l + &(&alpha2 * (&table, &numerator_constant_b_wire.0));
    sum_num_constant_l = &sum_num_constant_l + &(&alpha * (&table, &numerator_constant_c_wire.0));
    sum_num_constant_l = &sum_num_constant_l + &numerator_constant_op.0;

    let mut sum_num_constant_r = &alpha3 * (&table, &numerator_constant_a_wire.1);
    sum_num_constant_r = &sum_num_constant_r + &(&alpha2 * (&table, &numerator_constant_b_wire.1));
    sum_num_constant_r = &sum_num_constant_r + &(&alpha * (&table, &numerator_constant_c_wire.1));
    sum_num_constant_r = &sum_num_constant_r + &numerator_constant_op.1;

    let alpha8: QM31Var = worm.read("line_batch_random_coeff_8")?;

    let alpha8constant_l = &alpha8 * (&table, &sum_num_constant_l);
    let alpha8constant_r = &alpha8 * (&table, &sum_num_constant_r);

    worm.write(format!("alpha8constant_{}_l", query_idx), &alpha8constant_l)?;
    worm.write(format!("alpha8constant_{}_r", query_idx), &alpha8constant_r)?;

    let prepared_oods_shifted_by_1_a: CM31Var = worm.read("prepared_oods_shifted_by_1_a")?;
    let prepared_oods_shifted_by_1_b: CM31Var = worm.read("prepared_oods_shifted_by_1_b")?;

    let denominator_inverse_var = denominator_inverse_from_prepared(
        &table,
        &prepared_oods_shifted_by_1_a,
        &prepared_oods_shifted_by_1_b,
        &x,
        &y,
    );
    worm.write(
        format!("denominator_inverse_shifted_{}_l", query_idx),
        &denominator_inverse_var.0,
    )?;
    worm.write(
        format!("denominator_inverse_shifted_{}_r", query_idx),
        &denominator_inverse_var.1,
    )?;

    worm.save()?;
    Ok(cs)
}
