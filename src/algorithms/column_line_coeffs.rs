use crate::dsl::primitives::cm31::CM31Var;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use anyhow::Result;

/// Compute the parameters of `column_line_coeffs` without applying alpha.
///
/// Input:
/// - `table`, by reference
/// - `p.y, f1(p), f2(p), ..., fn(p)`, all of which are QM31 (not yet decomposed)
///
/// Output:
/// - `(a1, b1), (a2, b2), (a3, b3), ..., (an, bn)`
///   where all of them are cm31.
/// - `ai = Im(f(P)) / Im(p.y)`
/// - `bi = Im(f(P)) / Im(p.y) Re(p.y) - Re(f(P))`
///
pub fn column_line_coeffs(
    table: &TableVar,
    y: &QM31Var,
    evals: &[QM31Var],
) -> Result<Vec<(CM31Var, CM31Var)>> {
    let y_second_inverse = y.second.inverse(table);
    let y_first_times_y_second_inv = &y.first * &y_second_inverse;

    let mut ab = vec![];

    for eval in evals.iter() {
        let a = &eval.second * (table, &y_second_inverse);
        let b = &(&eval.second * (table, &y_first_times_y_second_inv)) - &eval.first;
        ab.push((a, b));
    }

    Ok(ab)
}
