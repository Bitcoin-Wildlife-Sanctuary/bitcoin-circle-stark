use crate::dsl::plonk::hints::Hints;
use anyhow::Result;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::worm::WORMMemory;

pub fn generate_cs(_: &Hints, worm: &mut WORMMemory) -> Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    worm.init(&cs)?;
    worm.check()?;
    worm.save()?;
    Ok(cs)
}
