use crate::dsl::primitives::cm31::CM31Var;
use crate::dsl::primitives::m31::M31Var;
use crate::dsl::primitives::table::TableVar;

pub fn apply_twin(
    table: &TableVar,
    z_y: &M31Var,
    queried_value_for_z: &M31Var,
    queried_value_for_conjugated_z: &M31Var,
    a: &CM31Var,
    b: &CM31Var,
) -> (CM31Var, CM31Var) {
    let a_times_z_y = a * (table, z_y);

    let res_z = &(b - &a_times_z_y) + queried_value_for_z;
    let res_conjugated_z = &(b + &a_times_z_y) + queried_value_for_conjugated_z;

    (res_z, res_conjugated_z)
}

pub fn denominator_inverse_from_prepared(
    table: &TableVar,
    x_second_div_y_second: &CM31Var,
    cross_term: &CM31Var,
    z_x: &M31Var,
    z_y: &M31Var,
) -> (CM31Var, CM31Var) {
    let cross_term_plus_z_x = cross_term + z_x;
    let x_second_div_y_second_times_z_y = x_second_div_y_second * (table, z_y);

    let result_for_z = &cross_term_plus_z_x - &x_second_div_y_second_times_z_y;
    let result_for_conjugated_z = &cross_term_plus_z_x + &x_second_div_y_second_times_z_y;

    let inverse_result_for_z = result_for_z.inverse(table);
    let inverse_result_for_conjugated_z = result_for_conjugated_z.inverse(table);

    (inverse_result_for_z, inverse_result_for_conjugated_z)
}
