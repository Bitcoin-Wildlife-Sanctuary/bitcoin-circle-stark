use crate::algorithms::quotient::apply_twin;
use crate::dsl::plonk::hints::Hints;
use anyhow::Result;
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
) -> Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    worm.init(&cs)?;

    let y: M31Var = worm.read(format!("circle_point_y_{}", query_idx))?;
    let table = TableVar::new_constant(&cs, ())?;

    let interaction_l: QM31Var =
        worm.read(format!("interaction_ab_queried_results_{}_l", query_idx))?;
    let interaction_r: QM31Var =
        worm.read(format!("interaction_ab_queried_results_{}_r", query_idx))?;

    let mut column_line_interaction_vars = Vec::<(CM31Var, CM31Var)>::new();
    for i in 0..4 {
        column_line_interaction_vars.push((
            worm.read(format!("column_line_coeffs_interaction_{}_a", i))?,
            worm.read(format!("column_line_coeffs_interaction_{}_b", i))?,
        ))
    }

    let numerator_interaction_0 = apply_twin(
        &table,
        &y,
        &interaction_l.first.real,
        &interaction_r.first.real,
        &column_line_interaction_vars[0].0,
        &column_line_interaction_vars[0].1,
    );

    let numerator_interaction_1 = apply_twin(
        &table,
        &y,
        &interaction_l.first.imag,
        &interaction_r.first.imag,
        &column_line_interaction_vars[1].0,
        &column_line_interaction_vars[1].1,
    );

    let numerator_interaction_2 = apply_twin(
        &table,
        &y,
        &interaction_l.second.real,
        &interaction_r.second.real,
        &column_line_interaction_vars[2].0,
        &column_line_interaction_vars[2].1,
    );

    let numerator_interaction_3 = apply_twin(
        &table,
        &y,
        &interaction_l.second.imag,
        &interaction_r.second.imag,
        &column_line_interaction_vars[3].0,
        &column_line_interaction_vars[3].1,
    );

    let alpha3: QM31Var = worm.read("line_batch_random_coeff_3")?;
    let alpha2: QM31Var = worm.read("line_batch_random_coeff_2")?;
    let alpha: QM31Var = worm.read("line_batch_random_coeff")?;

    let mut sum_num_interaction_l = &alpha3 * (&table, &numerator_interaction_0.0);
    sum_num_interaction_l =
        &sum_num_interaction_l + &(&alpha2 * (&table, &numerator_interaction_1.0));
    sum_num_interaction_l =
        &sum_num_interaction_l + &(&alpha * (&table, &numerator_interaction_2.0));
    sum_num_interaction_l = &sum_num_interaction_l + &numerator_interaction_3.0;

    let mut sum_num_interaction_r = &alpha3 * (&table, &numerator_interaction_0.1);
    sum_num_interaction_r =
        &sum_num_interaction_r + &(&alpha2 * (&table, &numerator_interaction_1.1));
    sum_num_interaction_r =
        &sum_num_interaction_r + &(&alpha * (&table, &numerator_interaction_2.1));
    sum_num_interaction_r = &sum_num_interaction_r + &numerator_interaction_3.1;

    let alpha4: QM31Var = worm.read("line_batch_random_coeff_4")?;
    let alpha4interaction_ab_l = &alpha4 * (&table, &sum_num_interaction_l);
    let alpha4interaction_ab_r = &alpha4 * (&table, &sum_num_interaction_r);

    worm.write(
        format!("alpha4interaction_ab_{}_l", query_idx),
        &alpha4interaction_ab_l,
    )?;
    worm.write(
        format!("alpha4interaction_ab_{}_r", query_idx),
        &alpha4interaction_ab_r,
    )?;

    worm.save()?;
    Ok(cs)
}
