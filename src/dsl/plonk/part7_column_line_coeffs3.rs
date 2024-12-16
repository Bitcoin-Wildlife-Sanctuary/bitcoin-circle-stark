use crate::algorithms::column_line_coeffs::column_line_coeffs;
use crate::dsl::plonk::hints::Hints;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use anyhow::Result;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::ldm::LDM;

pub fn generate_cs(_: &Hints, ldm: &mut LDM) -> Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    ldm.init(&cs)?;

    let mut interaction_oods_values = Vec::<QM31Var>::new();
    for i in [5, 7, 9, 11].iter() {
        interaction_oods_values.push(ldm.read(format!("interaction_oods_value_{}", i))?);
    }

    let oods_shifted_by_1_y: QM31Var = ldm.read("oods_shifted_by_1_y")?;

    let table = TableVar::new_constant(&cs, ())?;

    let res = column_line_coeffs(&table, &oods_shifted_by_1_y, &interaction_oods_values)?;

    for i in 0..4 {
        ldm.write(
            format!("column_line_coeffs_interaction_shifted_{}_a", i),
            &res[i].0,
        )?;
        ldm.write(
            format!("column_line_coeffs_interaction_shifted_{}_b", i),
            &res[i].1,
        )?;
    }

    let mut constant_oods_values = Vec::<QM31Var>::new();
    for i in 0..4 {
        constant_oods_values.push(ldm.read(format!("constant_oods_value_{}", i))?);
    }

    let oods_y: QM31Var = ldm.read("oods_y")?;

    let res = column_line_coeffs(&table, &oods_y, &constant_oods_values)?;

    for i in 0..4 {
        ldm.write(format!("column_line_coeffs_constant_{}_a", i), &res[i].0)?;
        ldm.write(format!("column_line_coeffs_constant_{}_b", i), &res[i].1)?;
    }

    ldm.save()?;
    Ok(cs)
}
