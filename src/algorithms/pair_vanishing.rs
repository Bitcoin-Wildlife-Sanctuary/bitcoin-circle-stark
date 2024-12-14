use crate::algorithms::point::SecureCirclePointVar;
use crate::dsl::primitives::cm31::CM31Var;
use crate::dsl::primitives::table::TableVar;

pub fn prepare_pair_vanishing(
    point: &SecureCirclePointVar,
    table: &TableVar,
) -> (CM31Var, CM31Var) {
    // note: there are some overlapping regarding the extraction of `y_imag` and `y_real` between
    // this function and `column_line_coeffs` and they can be combined.

    let y_second_inv = point.y.second.inverse(table);
    let x_second_div_y_second = &point.x.second * (table, &y_second_inv);

    let mut cross_term = &x_second_div_y_second * (table, &point.y.first);
    cross_term = &cross_term - &point.x.first;

    (x_second_div_y_second, cross_term)
}
