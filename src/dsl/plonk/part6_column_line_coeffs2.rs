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
    for i in [0, 1, 2, 3, 4, 6, 8, 10].iter() {
        interaction_oods_values.push(ldm.read(format!("interaction_oods_value_{}", i))?);
    }

    let oods_y: QM31Var = ldm.read("oods_y")?;

    let table = TableVar::new_constant(&cs, ())?;

    let res = column_line_coeffs(&table, &oods_y, &interaction_oods_values)?;

    for i in 0..8 {
        ldm.write(format!("column_line_coeffs_interaction_{}_a", i), &res[i].0)?;
        ldm.write(format!("column_line_coeffs_interaction_{}_b", i), &res[i].1)?;
    }

    ldm.save()?;
    Ok(cs)
}
