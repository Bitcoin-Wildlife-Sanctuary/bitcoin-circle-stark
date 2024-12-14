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

    let interaction_l: QM31Var =
        ldm.read(format!("interaction_cum_queried_results_{}_l", query_idx))?;
    let interaction_r: QM31Var =
        ldm.read(format!("interaction_cum_queried_results_{}_r", query_idx))?;

    let mut column_line_interaction_shifted_vars = Vec::<(CM31Var, CM31Var)>::new();
    for i in 0..4 {
        column_line_interaction_shifted_vars.push((
            ldm.read(format!("column_line_coeffs_interaction_shifted_{}_a", i))?,
            ldm.read(format!("column_line_coeffs_interaction_shifted_{}_b", i))?,
        ))
    }

    let numerator_interaction_shifted_0 = apply_twin(
        &table,
        &y,
        &interaction_l.first.real,
        &interaction_r.first.real,
        &column_line_interaction_shifted_vars[0].0,
        &column_line_interaction_shifted_vars[0].1,
    );

    let numerator_interaction_shifted_1 = apply_twin(
        &table,
        &y,
        &interaction_l.first.imag,
        &interaction_r.first.imag,
        &column_line_interaction_shifted_vars[1].0,
        &column_line_interaction_shifted_vars[1].1,
    );

    let numerator_interaction_shifted_2 = apply_twin(
        &table,
        &y,
        &interaction_l.second.real,
        &interaction_r.second.real,
        &column_line_interaction_shifted_vars[2].0,
        &column_line_interaction_shifted_vars[2].1,
    );

    let numerator_interaction_shifted_3 = apply_twin(
        &table,
        &y,
        &interaction_l.second.imag,
        &interaction_r.second.imag,
        &column_line_interaction_shifted_vars[3].0,
        &column_line_interaction_shifted_vars[3].1,
    );

    let alpha3: QM31Var = ldm.read("line_batch_random_coeff_3")?;
    let alpha2: QM31Var = ldm.read("line_batch_random_coeff_2")?;
    let alpha: QM31Var = ldm.read("line_batch_random_coeff")?;

    let mut sum_num_interaction_shifted_l = &alpha3 * (&table, &numerator_interaction_shifted_0.0);
    sum_num_interaction_shifted_l =
        &sum_num_interaction_shifted_l + &(&alpha2 * (&table, &numerator_interaction_shifted_1.0));
    sum_num_interaction_shifted_l =
        &sum_num_interaction_shifted_l + &(&alpha * (&table, &numerator_interaction_shifted_2.0));
    sum_num_interaction_shifted_l =
        &sum_num_interaction_shifted_l + &numerator_interaction_shifted_3.0;

    let mut sum_num_interaction_shifted_r = &alpha3 * (&table, &numerator_interaction_shifted_0.1);
    sum_num_interaction_shifted_r =
        &sum_num_interaction_shifted_r + &(&alpha2 * (&table, &numerator_interaction_shifted_1.1));
    sum_num_interaction_shifted_r =
        &sum_num_interaction_shifted_r + &(&alpha * (&table, &numerator_interaction_shifted_2.1));
    sum_num_interaction_shifted_r =
        &sum_num_interaction_shifted_r + &numerator_interaction_shifted_3.1;

    let denominator_inverse_shifted_l: CM31Var =
        ldm.read(format!("denominator_inverse_shifted_{}_l", query_idx))?;
    let denominator_inverse_shifted_r: CM31Var =
        ldm.read(format!("denominator_inverse_shifted_{}_r", query_idx))?;

    let quotient_term2_l =
        &sum_num_interaction_shifted_l * (&table, &denominator_inverse_shifted_l);
    let quotient_term2_r =
        &sum_num_interaction_shifted_r * (&table, &denominator_inverse_shifted_r);

    ldm.write(format!("quotient_term2_{}_l", query_idx), &quotient_term2_l)?;
    ldm.write(format!("quotient_term2_{}_r", query_idx), &quotient_term2_r)?;

    ldm.save()?;
    Ok(cs)
}
