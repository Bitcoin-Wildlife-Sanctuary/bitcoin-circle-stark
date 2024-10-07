use crate::algorithms::pair_vanishing::prepare_pair_vanishing;
use crate::algorithms::point::SecureCirclePointVar;
use crate::dsl::plonk::hints::Hints;
use bitcoin_script_dsl::builtins::qm31::QM31Var;
use bitcoin_script_dsl::builtins::table::TableVar;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::constraint_system::{ConstraintSystem, ConstraintSystemRef};
use bitcoin_script_dsl::worm::WORMMemory;

pub fn generate_cs(_: &Hints, worm: &mut WORMMemory) -> anyhow::Result<ConstraintSystemRef> {
    let cs = ConstraintSystem::new_ref();
    worm.init(&cs)?;

    let oods_x: QM31Var = worm.read("oods_x")?;
    let oods_y: QM31Var = worm.read("oods_y")?;

    let oods_point = SecureCirclePointVar {
        x: oods_x,
        y: oods_y,
    };

    let table = TableVar::new_constant(&cs, ())?;

    let prepared_oods = prepare_pair_vanishing(&oods_point, &table);
    worm.write("prepared_oods_a", &prepared_oods.0)?;
    worm.write("prepared_oods_b", &prepared_oods.1)?;

    let oods_shifted_by_1_x: QM31Var = worm.read("oods_shifted_by_1_x")?;
    let oods_shifted_by_1_y: QM31Var = worm.read("oods_shifted_by_1_y")?;

    let oods_shifted_by_1_point = SecureCirclePointVar {
        x: oods_shifted_by_1_x,
        y: oods_shifted_by_1_y,
    };

    let prepared_oods_shifted_by_1 = prepare_pair_vanishing(&oods_shifted_by_1_point, &table);
    worm.write(
        "prepared_oods_shifted_by_1_a",
        &prepared_oods_shifted_by_1.0,
    )?;
    worm.write(
        "prepared_oods_shifted_by_1_b",
        &prepared_oods_shifted_by_1.1,
    )?;

    let alpha: QM31Var = worm.read("line_batch_random_coeff")?;

    // The needed alphas are:
    // - alpha, alpha^2, alpha^3, alpha^4, alpha^8, alpha^12, alpha^20

    let alpha2 = &alpha * (&table, &alpha);
    let alpha3 = &alpha2 * (&table, &alpha);
    let alpha4 = &alpha2 * (&table, &alpha2);
    let alpha8 = &alpha4 * (&table, &alpha4);
    let alpha12 = &alpha8 * (&table, &alpha4);
    let alpha20 = &alpha8 * (&table, &alpha12);

    worm.write("line_batch_random_coeff_2", &alpha2)?;
    worm.write("line_batch_random_coeff_3", &alpha3)?;
    worm.write("line_batch_random_coeff_4", &alpha4)?;
    worm.write("line_batch_random_coeff_8", &alpha8)?;
    worm.write("line_batch_random_coeff_12", &alpha12)?;
    worm.write("line_batch_random_coeff_20", &alpha20)?;

    worm.save()?;
    Ok(cs)
}
