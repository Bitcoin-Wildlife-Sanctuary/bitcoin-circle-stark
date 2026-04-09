//! Compose M31/CM31/QM31 multiplications through the DSL compiler and print
//! the resulting compiled script length. This captures the full cost of a
//! multiplication (limb decomposition + mul gadget + reduction) and also the
//! size of the multiplication table that must be pushed on the stack.

use bitcoin_circle_stark::dsl::primitives::cm31::CM31Var;
use bitcoin_circle_stark::dsl::primitives::m31::M31Var;
use bitcoin_circle_stark::dsl::primitives::qm31::QM31Var;
use bitcoin_circle_stark::dsl::primitives::table::TableVar;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::compiler::Compiler;
use bitcoin_script_dsl::constraint_system::ConstraintSystem;
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

fn main() {
    // ---------------- baseline: push the table ----------------
    {
        let cs = ConstraintSystem::new_ref();
        let _table = TableVar::new_constant(&cs, ()).unwrap();
        let program = Compiler::compile(cs).unwrap();
        println!(
            "[baseline] push TableVar (513 entries)        = {:>6} bytes",
            program.script.len()
        );
    }

    // ---------------- M31 × M31 through the table ----------------
    {
        let cs = ConstraintSystem::new_ref();
        let a = M31Var::new_constant(&cs, M31::from_u32_unchecked(1234)).unwrap();
        let b = M31Var::new_constant(&cs, M31::from_u32_unchecked(5678)).unwrap();
        let table = TableVar::new_constant(&cs, ()).unwrap();
        let _c = &a * (&table, &b);
        let program = Compiler::compile(cs).unwrap();
        println!(
            "M31 mul (table, with table push)              = {:>6} bytes",
            program.script.len()
        );
    }

    // ---------------- CM31 × CM31 through the table ----------------
    {
        let cs = ConstraintSystem::new_ref();
        let a = CM31Var::new_constant(
            &cs,
            CM31::from_m31(M31::from_u32_unchecked(1), M31::from_u32_unchecked(2)),
        )
        .unwrap();
        let b = CM31Var::new_constant(
            &cs,
            CM31::from_m31(M31::from_u32_unchecked(3), M31::from_u32_unchecked(4)),
        )
        .unwrap();
        let table = TableVar::new_constant(&cs, ()).unwrap();
        let _c = &a * (&table, &b);
        let program = Compiler::compile(cs).unwrap();
        println!(
            "CM31 mul (table, with table push)             = {:>6} bytes",
            program.script.len()
        );
    }

    // ---------------- QM31 × QM31 through the table ----------------
    {
        let cs = ConstraintSystem::new_ref();
        let a = QM31Var::new_constant(&cs, QM31::from_u32_unchecked(1, 2, 3, 4)).unwrap();
        let b = QM31Var::new_constant(&cs, QM31::from_u32_unchecked(5, 6, 7, 8)).unwrap();
        let table = TableVar::new_constant(&cs, ()).unwrap();
        let _c = &a * (&table, &b);
        let program = Compiler::compile(cs).unwrap();
        println!(
            "QM31 mul (table, with table push)             = {:>6} bytes",
            program.script.len()
        );
    }

    // ---------------- incremental muls sharing the table ----------------
    for k in [1usize, 2, 4, 8] {
        let cs = ConstraintSystem::new_ref();
        let a = QM31Var::new_constant(&cs, QM31::from_u32_unchecked(1, 2, 3, 4)).unwrap();
        let b = QM31Var::new_constant(&cs, QM31::from_u32_unchecked(5, 6, 7, 8)).unwrap();
        let table = TableVar::new_constant(&cs, ()).unwrap();
        let mut acc = &a * (&table, &b);
        for _ in 1..k {
            acc = &acc * (&table, &b);
        }
        let program = Compiler::compile(cs).unwrap();
        println!(
            "{:>2} x QM31 mul (amortized, with table push)  = {:>6} bytes",
            k,
            program.script.len()
        );
    }

    // ---------------- QM31 mul *without* using the table ----------------
    {
        let cs = ConstraintSystem::new_ref();
        let a = QM31Var::new_constant(&cs, QM31::from_u32_unchecked(1, 2, 3, 4)).unwrap();
        let b = QM31Var::new_constant(&cs, QM31::from_u32_unchecked(5, 6, 7, 8)).unwrap();
        let _c = &a * &b;
        let program = Compiler::compile(cs).unwrap();
        println!(
            "QM31 mul (non-table, rust_bitcoin_m31)        = {:>6} bytes",
            program.script.len()
        );
    }
    {
        let cs = ConstraintSystem::new_ref();
        let a = M31Var::new_constant(&cs, M31::from_u32_unchecked(1234)).unwrap();
        let b = M31Var::new_constant(&cs, M31::from_u32_unchecked(5678)).unwrap();
        let _c = &a * &b;
        let program = Compiler::compile(cs).unwrap();
        println!(
            "M31 mul (non-table, rust_bitcoin_m31)         = {:>6} bytes",
            program.script.len()
        );
    }
}
