use crate::dsl::primitives::channel::HashVarWithChannel;
use crate::dsl::primitives::m31::M31Var;
use crate::dsl::primitives::qm31::QM31Var;
use crate::dsl::primitives::table::TableVar;
use bitcoin_script_dsl::builtins::hash::HashVar;
use bitcoin_script_dsl::bvar::{AllocVar, BVar};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::M31;

pub struct SecureCirclePointVar {
    pub x: QM31Var,
    pub y: QM31Var,
}

pub fn get_oods_point(hash: &mut HashVar, table: &TableVar) -> SecureCirclePointVar {
    let t = hash.draw_felt();
    let t_doubled = &t + &t;
    let t_squared = &t * (table, &t);

    let t_squared_plus_1 = t_squared.add1();
    let t_squared_minus_1 = t_squared.sub1();

    let t_squared_plus_1_inverse = t_squared_plus_1.inverse(table);

    let x = &(-&t_squared_minus_1) * (table, &t_squared_plus_1_inverse);
    let y = &t_doubled * (table, &t_squared_plus_1_inverse);

    SecureCirclePointVar { x, y }
}

pub fn add_constant_m31_point_x_only(
    point: &SecureCirclePointVar,
    table: &TableVar,
    constant: CirclePoint<M31>,
) -> QM31Var {
    let cs = point.x.cs().and(&point.y.cs()).and(&table.cs());

    // new x: x0 · x1 − y0 · y1
    let x0 = point.x.clone();
    let y0 = point.y.clone();

    let x1 = M31Var::new_constant(&cs, constant.x).unwrap();
    let y1 = M31Var::new_constant(&cs, constant.y).unwrap();

    &(&x0 * (table, &x1)) - &(&y0 * (table, &y1))
}

pub fn add_constant_m31_point(
    point: &SecureCirclePointVar,
    table: &TableVar,
    constant: CirclePoint<M31>,
) -> SecureCirclePointVar {
    let cs = point.x.cs().and(&point.y.cs()).and(&table.cs());

    // new x: x0 · x1 − y0 · y1
    // new y: x0 · y1 + y0 · x1
    // use Karatsuba

    let x0 = point.x.clone();
    let y0 = point.y.clone();

    let x1 = M31Var::new_constant(&cs, constant.x).unwrap();
    let y1 = M31Var::new_constant(&cs, constant.y).unwrap();

    let x0x1 = &x0 * (table, &x1);
    let y0y1 = &y0 * (table, &y1);

    let x0_plus_y0 = &x0 + &y0;
    let x1_plus_y1 = constant.x + constant.y;
    let x1_plus_y1 = M31Var::new_constant(&cs, x1_plus_y1).unwrap();

    let all_terms = &x0_plus_y0 * (table, &x1_plus_y1);
    let mut cross_terms = &all_terms - &x0x1;
    cross_terms = &cross_terms - &y0y1;

    let x = &x0x1 - &y0y1;
    let y = cross_terms;

    SecureCirclePointVar { x, y }
}
