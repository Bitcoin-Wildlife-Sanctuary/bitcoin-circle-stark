use crate::dsl::plonk::hints::Hints;
use crate::dsl::primitives::cm31::CM31Var;
use crate::dsl::primitives::m31::M31Var;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use bitcoin_script_dsl::bvar::{AllocVar, BVar};
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::ldm::LDM;

pub fn generate_cs(
    _: &Hints,
    ldm: &mut LDM,
    query_idx: usize,
) -> anyhow::Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    ldm.init(&cs)?;

    let quotient_term1_num_l: QM31Var = ldm.read(format!("quotient_term1_num_{}_l", query_idx))?;
    let quotient_term1_num_r: QM31Var = ldm.read(format!("quotient_term1_num_{}_r", query_idx))?;

    let denominator_inverse_l: CM31Var =
        ldm.read(format!("denominator_inverse_{}_l", query_idx))?;
    let denominator_inverse_r: CM31Var =
        ldm.read(format!("denominator_inverse_{}_r", query_idx))?;

    let table = TableVar::new_constant(&cs, ())?;

    let quotient_term1_l = &quotient_term1_num_l * (&table, &denominator_inverse_l);
    let quotient_term1_r = &quotient_term1_num_r * (&table, &denominator_inverse_r);

    let quotient_term2_l: QM31Var = ldm.read(format!("quotient_term2_{}_l", query_idx))?;
    let quotient_term2_r: QM31Var = ldm.read(format!("quotient_term2_{}_r", query_idx))?;

    let quotient_l = &quotient_term1_l + &quotient_term2_l;
    let quotient_r = &quotient_term1_r + &quotient_term2_r;

    let y: M31Var = ldm.read(format!("circle_point_y_{}", query_idx))?;
    let y_inv = y.inverse(&table);

    let ifft_results_vars = {
        let new_v0 = &quotient_l + &quotient_r;
        let diff = &quotient_l - &quotient_r;
        let new_v1 = &diff * (&table, &y_inv);
        (new_v0, new_v1)
    };

    let fri_fold_random_coeff_var: QM31Var = ldm.read("fri_fold_random_coeff")?;
    let mut folded_result = &fri_fold_random_coeff_var * (&table, &ifft_results_vars.1);
    folded_result = &folded_result + &ifft_results_vars.0;

    let expected_entry_quotient: QM31Var =
        ldm.read(format!("expected_entry_quotient_{}", query_idx))?;
    expected_entry_quotient.equalverify(&folded_result)?;

    ldm.save()?;
    Ok(cs)
}
