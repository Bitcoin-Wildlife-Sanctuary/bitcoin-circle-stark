use crate::algorithms::column_line_coeffs::column_line_coeffs;
use crate::dsl::plonk::hints::Hints;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::ldm::LDM;

pub fn generate_cs(_: &Hints, ldm: &mut LDM) -> anyhow::Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    ldm.init(&cs)?;

    let oods_y: QM31Var = ldm.read("oods_y")?;
    let table = TableVar::new_constant(&cs, ())?;

    let mult_var: QM31Var = ldm.read("trace_oods_value_0")?;
    let a_val_var: QM31Var = ldm.read("trace_oods_value_1")?;
    let b_val_var: QM31Var = ldm.read("trace_oods_value_2")?;
    let c_val_var: QM31Var = ldm.read("trace_oods_value_3")?;

    let res = column_line_coeffs(
        &table,
        &oods_y,
        &[mult_var, a_val_var, b_val_var, c_val_var],
    )?;

    for i in 0..4 {
        ldm.write(format!("column_line_coeffs_trace_{}_a", i), &res[i].0)?;
        ldm.write(format!("column_line_coeffs_trace_{}_b", i), &res[i].1)?;
    }

    let composition_0_var: QM31Var = ldm.read("composition_oods_value_0")?;
    let composition_1_var: QM31Var = ldm.read("composition_oods_value_1")?;
    let composition_2_var: QM31Var = ldm.read("composition_oods_value_2")?;
    let composition_3_var: QM31Var = ldm.read("composition_oods_value_3")?;

    let res = column_line_coeffs(
        &table,
        &oods_y,
        &[
            composition_0_var,
            composition_1_var,
            composition_2_var,
            composition_3_var,
        ],
    )?;

    for i in 0..4 {
        ldm.write(format!("column_line_coeffs_composition_{}_a", i), &res[i].0)?;
        ldm.write(format!("column_line_coeffs_composition_{}_b", i), &res[i].1)?;
    }

    ldm.save()?;
    Ok(cs)
}
