use crate::algorithms::point::{
    add_constant_m31_point, add_constant_m31_point_x_only, SecureCirclePointVar,
};
use crate::dsl::plonk::hints::{Hints, LOG_N_ROWS};
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use anyhow::Result;
use bitcoin_script_dsl::bvar::{AllocVar, BVar};
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::ldm::LDM;
use stwo_prover::core::poly::circle::CanonicCoset;

pub fn generate_cs(_: &Hints, ldm: &mut LDM) -> Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    ldm.init(&cs)?;

    let oods_x: QM31Var = ldm.read("oods_x")?;
    let oods_y: QM31Var = ldm.read("oods_y")?;

    let oods_point = SecureCirclePointVar {
        x: oods_x,
        y: oods_y,
    };

    let table = TableVar::new_constant(&cs, ())?;

    let coset = CanonicCoset::new(LOG_N_ROWS).coset;
    let shift = -coset.initial + coset.step_size.half().to_point();
    let mut cur_x = add_constant_m31_point_x_only(&oods_point, &table, shift);
    for _ in 1..coset.log_size {
        cur_x = &cur_x * (&table, &cur_x);
        cur_x = &cur_x + &cur_x;
        cur_x = cur_x.sub1();
    }

    let constraint_denom = cur_x.inverse(&table);

    let constraint_num: QM31Var = ldm.read("constraint_num")?;
    let computed_composition = &constraint_denom * (&table, &constraint_num);

    let composition_0_var: QM31Var = ldm.read("composition_oods_value_0")?;
    let composition_1_var: QM31Var = ldm.read("composition_oods_value_1")?;
    let composition_2_var: QM31Var = ldm.read("composition_oods_value_2")?;
    let composition_3_var: QM31Var = ldm.read("composition_oods_value_3")?;

    let mut composition_var = &composition_0_var + &composition_1_var.shift_by_i();
    composition_var = &composition_var + &composition_2_var.shift_by_j();
    composition_var = &composition_var + &composition_3_var.shift_by_ij();

    computed_composition.equalverify(&composition_var)?;

    // shift the oods point
    let trace_step = CanonicCoset::new(LOG_N_ROWS).step();
    let shift_minus_1 = trace_step.mul_signed(-1);

    let oods_shifted_by_1 = add_constant_m31_point(&oods_point, &table, shift_minus_1);

    ldm.write("oods_shifted_by_1_x", &oods_shifted_by_1.x)?;
    ldm.write("oods_shifted_by_1_y", &oods_shifted_by_1.y)?;

    ldm.save()?;
    Ok(cs)
}
