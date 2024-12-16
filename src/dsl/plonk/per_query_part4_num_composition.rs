use crate::algorithms::quotient::apply_twin;
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

    let y: M31Var = ldm.read(format!("circle_point_y_{}", query_idx))?;
    let table = TableVar::new_constant(&cs, ())?;

    let composition_l: QM31Var =
        ldm.read(format!("composition_queried_results_{}_l", query_idx))?;
    let composition_r: QM31Var =
        ldm.read(format!("composition_queried_results_{}_r", query_idx))?;

    let mut column_line_composition_vars = Vec::<(CM31Var, CM31Var)>::new();
    for i in 0..4 {
        column_line_composition_vars.push((
            ldm.read(format!("column_line_coeffs_composition_{}_a", i))?,
            ldm.read(format!("column_line_coeffs_composition_{}_b", i))?,
        ))
    }

    let numerator_composition_0 = apply_twin(
        &table,
        &y,
        &composition_l.first.real,
        &composition_r.first.real,
        &column_line_composition_vars[0].0,
        &column_line_composition_vars[0].1,
    );

    let numerator_composition_1 = apply_twin(
        &table,
        &y,
        &composition_l.first.imag,
        &composition_r.first.imag,
        &column_line_composition_vars[1].0,
        &column_line_composition_vars[1].1,
    );

    let numerator_composition_2 = apply_twin(
        &table,
        &y,
        &composition_l.second.real,
        &composition_r.second.real,
        &column_line_composition_vars[2].0,
        &column_line_composition_vars[2].1,
    );

    let numerator_composition_3 = apply_twin(
        &table,
        &y,
        &composition_l.second.imag,
        &composition_r.second.imag,
        &column_line_composition_vars[3].0,
        &column_line_composition_vars[3].1,
    );

    let alpha3: QM31Var = ldm.read("line_batch_random_coeff_3")?;
    let alpha2: QM31Var = ldm.read("line_batch_random_coeff_2")?;
    let alpha: QM31Var = ldm.read("line_batch_random_coeff")?;

    let mut sum_num_composition_l = &alpha3 * (&table, &numerator_composition_0.0);
    sum_num_composition_l =
        &sum_num_composition_l + &(&alpha2 * (&table, &numerator_composition_1.0));
    sum_num_composition_l =
        &sum_num_composition_l + &(&alpha * (&table, &numerator_composition_2.0));
    sum_num_composition_l = &sum_num_composition_l + &numerator_composition_3.0;

    let mut sum_num_composition_r = &alpha3 * (&table, &numerator_composition_0.1);
    sum_num_composition_r =
        &sum_num_composition_r + &(&alpha2 * (&table, &numerator_composition_1.1));
    sum_num_composition_r =
        &sum_num_composition_r + &(&alpha * (&table, &numerator_composition_2.1));
    sum_num_composition_r = &sum_num_composition_r + &numerator_composition_3.1;

    let alpha4: QM31Var = ldm.read("line_batch_random_coeff_4")?;

    let alpha4composition_l = &alpha4 * (&table, &sum_num_composition_l);
    let alpha4composition_r = &alpha4 * (&table, &sum_num_composition_r);

    ldm.write(
        format!("alpha4composition_{}_l", query_idx),
        &alpha4composition_l,
    )?;
    ldm.write(
        format!("alpha4composition_{}_r", query_idx),
        &alpha4composition_r,
    )?;

    ldm.save()?;
    Ok(cs)
}
