use crate::algorithms::column_line_coeffs::column_line_coeffs;
use crate::dsl::plonk::hints::Hints;
use anyhow::Result;
use bitcoin_script_dsl::builtins::qm31::QM31Var;
use bitcoin_script_dsl::builtins::table::TableVar;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::worm::WORMMemory;

pub fn generate_cs(_: &Hints, worm: &mut WORMMemory) -> Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    worm.init(&cs)?;

    let mut interaction_oods_values = Vec::<QM31Var>::new();
    for i in [5, 7, 9, 11].iter() {
        interaction_oods_values.push(worm.read(format!("interaction_oods_value_{}", i))?);
    }

    let oods_shifted_by_1_y: QM31Var = worm.read("oods_shifted_by_1_y")?;

    let table = TableVar::new_constant(&cs, ())?;

    let res = column_line_coeffs(&table, &oods_shifted_by_1_y, &interaction_oods_values)?;

    for i in 0..4 {
        worm.write(
            format!("column_line_coeffs_interaction_shifted_{}_a", i),
            &res[i].0,
        )?;
        worm.write(
            format!("column_line_coeffs_interaction_shifted_{}_b", i),
            &res[i].1,
        )?;
    }

    let mut constant_oods_values = Vec::<QM31Var>::new();
    for i in 0..4 {
        constant_oods_values.push(worm.read(format!("constant_oods_value_{}", i))?);
    }

    let oods_y: QM31Var = worm.read("oods_y")?;

    let res = column_line_coeffs(&table, &oods_y, &constant_oods_values)?;

    for i in 0..4 {
        worm.write(format!("column_line_coeffs_constant_{}_a", i), &res[i].0)?;
        worm.write(format!("column_line_coeffs_constant_{}_b", i), &res[i].1)?;
    }

    worm.save()?;
    Ok(cs)
}