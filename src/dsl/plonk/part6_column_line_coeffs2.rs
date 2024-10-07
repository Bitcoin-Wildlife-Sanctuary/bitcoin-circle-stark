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
    for i in [0, 1, 2, 3, 4, 6, 8, 10].iter() {
        interaction_oods_values.push(worm.read(format!("interaction_oods_value_{}", i))?);
    }

    let oods_y: QM31Var = worm.read("oods_y")?;

    let table = TableVar::new_constant(&cs, ())?;

    let res = column_line_coeffs(&table, &oods_y, &interaction_oods_values)?;

    for i in 0..8 {
        worm.write(format!("column_line_coeffs_interaction_{}_a", i), &res[i].0)?;
        worm.write(format!("column_line_coeffs_interaction_{}_b", i), &res[i].1)?;
    }

    worm.save()?;
    Ok(cs)
}
