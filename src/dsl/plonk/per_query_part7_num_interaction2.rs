use crate::algorithms::quotient::apply_twin;
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

    let y: M31Var = ldm.read(format!("circle_point_y_{}", query_idx))?;
    let table = TableVar::new_constant(&cs, ())?;

    let interaction_l: QM31Var =
        ldm.read(format!("interaction_cum_queried_results_{}_l", query_idx))?;
    let interaction_r: QM31Var =
        ldm.read(format!("interaction_cum_queried_results_{}_r", query_idx))?;

    let mut column_line_interaction_vars = Vec::<(CM31Var, CM31Var)>::new();
    for i in 0..4 {
        column_line_interaction_vars.push((
            ldm.read(format!("column_line_coeffs_interaction_{}_a", 4 + i))?,
            ldm.read(format!("column_line_coeffs_interaction_{}_b", 4 + i))?,
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

    let alpha3: QM31Var = ldm.read("line_batch_random_coeff_3")?;
    let alpha2: QM31Var = ldm.read("line_batch_random_coeff_2")?;
    let alpha: QM31Var = ldm.read("line_batch_random_coeff")?;

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

    let alpha4interaction_ab_l: QM31Var =
        ldm.read(format!("alpha4interaction_ab_{}_l", query_idx))?;
    let alpha4interaction_ab_r: QM31Var =
        ldm.read(format!("alpha4interaction_ab_{}_r", query_idx))?;

    let interaction_sum_l = &alpha4interaction_ab_l + &sum_num_interaction_l;
    let interaction_sum_r = &alpha4interaction_ab_r + &sum_num_interaction_r;

    let alpha12: QM31Var = ldm.read("line_batch_random_coeff_12")?;

    let alpha12interaction_sum_l = &alpha12 * (&table, &interaction_sum_l);
    let alpha12interaction_sum_r = &alpha12 * (&table, &interaction_sum_r);

    let alpha20trace_l: QM31Var = ldm.read(format!("alpha20trace_{}_l", query_idx))?;
    let alpha20trace_r: QM31Var = ldm.read(format!("alpha20trace_{}_r", query_idx))?;

    let mut quotient_term1_num_l = &alpha20trace_l + &alpha12interaction_sum_l;
    let mut quotient_term1_num_r = &alpha20trace_r + &alpha12interaction_sum_r;

    let alpha8constant_l: QM31Var = ldm.read(format!("alpha8constant_{}_l", query_idx))?;
    let alpha8constant_r: QM31Var = ldm.read(format!("alpha8constant_{}_r", query_idx))?;

    quotient_term1_num_l = &quotient_term1_num_l + &alpha8constant_l;
    quotient_term1_num_r = &quotient_term1_num_r + &alpha8constant_r;

    let alpha4composition_l: QM31Var = ldm.read(format!("alpha4composition_{}_l", query_idx))?;
    let alpha4composition_r: QM31Var = ldm.read(format!("alpha4composition_{}_r", query_idx))?;

    quotient_term1_num_l = &quotient_term1_num_l + &alpha4composition_l;
    quotient_term1_num_r = &quotient_term1_num_r + &alpha4composition_r;

    ldm.write(
        format!("quotient_term1_num_{}_l", query_idx),
        &quotient_term1_num_l,
    )?;
    ldm.write(
        format!("quotient_term1_num_{}_r", query_idx),
        &quotient_term1_num_r,
    )?;

    ldm.save()?;
    Ok(cs)
}
