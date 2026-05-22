//! Value-level correctness check for the `op-mulmod` model.
//!
//! The compiled scripts emit OP_MUL/OP_MOD, which are disabled in the script
//! interpreter, so the normal execution tests can't run under this feature.
//! Instead we confirm that the DSL value-tracking through the Karatsuba
//! composition matches native stwo field arithmetic. If the algebra in any
//! op-mulmod Mul impl were wrong, the assertions below would fire.
//!
//! Run: cargo run --bin verify_mulmod --features op-mulmod

use bitcoin_circle_stark::dsl::primitives::cm31::CM31Var;
use bitcoin_circle_stark::dsl::primitives::m31::M31Var;
use bitcoin_circle_stark::dsl::primitives::qm31::QM31Var;
use bitcoin_circle_stark::dsl::primitives::table::TableVar;
use bitcoin_script_dsl::bvar::{AllocVar, BVar};
use bitcoin_script_dsl::constraint_system::ConstraintSystem;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::fields::FieldExpOps;

fn m31(x: u32) -> M31 {
    M31::from_u32_unchecked(x)
}

fn main() {
    let cs = ConstraintSystem::new_ref();
    let table = TableVar::new_constant(&cs, ()).unwrap();

    // M31 × M31
    {
        let (a_val, b_val) = (m31(1234567), m31(7654321));
        let a = M31Var::new_constant(&cs, a_val).unwrap();
        let b = M31Var::new_constant(&cs, b_val).unwrap();
        let c = &a * (&table, &b);
        assert_eq!(c.value().unwrap(), a_val * b_val, "M31 mul");
    }

    // M31 inverse (hint + OP_MUL/OP_MOD check)
    {
        let a_val = m31(1234567);
        let a = M31Var::new_constant(&cs, a_val).unwrap();
        let inv = a.inverse(&table);
        assert_eq!(inv.value().unwrap(), a_val.inverse(), "M31 inverse");
        assert_eq!((a_val * inv.value().unwrap()).0, 1, "M31 inverse check");
    }

    // CM31 × CM31
    {
        let a_val = CM31::from_m31(m31(11), m31(22));
        let b_val = CM31::from_m31(m31(333), m31(444));
        let a = CM31Var::new_constant(&cs, a_val).unwrap();
        let b = CM31Var::new_constant(&cs, b_val).unwrap();
        let c = &a * (&table, &b);
        assert_eq!(c.value().unwrap(), a_val * b_val, "CM31 mul");
    }

    // CM31 × M31
    {
        let a_val = CM31::from_m31(m31(11), m31(22));
        let s_val = m31(99);
        let a = CM31Var::new_constant(&cs, a_val).unwrap();
        let s = M31Var::new_constant(&cs, s_val).unwrap();
        let c = &a * (&table, &s);
        assert_eq!(c.value().unwrap(), a_val * CM31::from(s_val), "CM31 x M31");
    }

    // QM31 × QM31
    {
        let a_val = QM31::from_u32_unchecked(2, 3, 5, 7);
        let b_val = QM31::from_u32_unchecked(11, 13, 17, 19);
        let a = QM31Var::new_constant(&cs, a_val).unwrap();
        let b = QM31Var::new_constant(&cs, b_val).unwrap();
        let c = &a * (&table, &b);
        assert_eq!(c.value().unwrap(), a_val * b_val, "QM31 mul");
    }

    // QM31 × CM31
    {
        let a_val = QM31::from_u32_unchecked(2, 3, 5, 7);
        let s_val = CM31::from_m31(m31(23), m31(29));
        let a = QM31Var::new_constant(&cs, a_val).unwrap();
        let s = CM31Var::new_constant(&cs, s_val).unwrap();
        let c = &a * (&table, &s);
        assert_eq!(c.value().unwrap(), a_val * QM31::from(s_val), "QM31 x CM31");
    }

    // QM31 × M31
    {
        let a_val = QM31::from_u32_unchecked(2, 3, 5, 7);
        let s_val = m31(31);
        let a = QM31Var::new_constant(&cs, a_val).unwrap();
        let s = M31Var::new_constant(&cs, s_val).unwrap();
        let c = &a * (&table, &s);
        assert_eq!(c.value().unwrap(), a_val * QM31::from(s_val), "QM31 x M31");
    }

    println!("all op-mulmod value checks passed");
}
