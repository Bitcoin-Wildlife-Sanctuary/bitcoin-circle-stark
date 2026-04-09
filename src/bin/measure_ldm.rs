//! Measure the per-operation cost of LDM (local data memory) writes and reads.
//! The LDM is the mechanism that compresses intermediate variables into a
//! running SHA256 hash so they can be passed across the 1000-stack-slot limit
//! to the next covenant split, then decompresses them via hints on the other
//! side. This binary isolates the LDM cost so we can see how much of the
//! "free-mul" residual comes from compression/decompression bookkeeping.

use bitcoin_circle_stark::dsl::primitives::m31::M31Var;
use bitcoin_circle_stark::dsl::primitives::qm31::QM31Var;
use bitcoin_script_dsl::bvar::AllocVar;
use bitcoin_script_dsl::compiler::Compiler;
use bitcoin_script_dsl::constraint_system::ConstraintSystem;
use bitcoin_script_dsl::ldm::LDM;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

fn main() {
    // 0 writes / 0 reads — pure LDM init/save plumbing
    let cs = ConstraintSystem::new_ref();
    let mut ldm = LDM::new();
    ldm.init(&cs).unwrap();
    ldm.save().unwrap();
    let base = Compiler::compile(cs).unwrap().script.len();
    println!("LDM init+save (baseline, 0 ops)        = {} bytes", base);

    // N writes of an M31
    for n in [1usize, 4, 16] {
        let cs = ConstraintSystem::new_ref();
        let mut ldm = LDM::new();
        ldm.init(&cs).unwrap();
        for i in 0..n {
            let v = M31Var::new_constant(&cs, M31::from_u32_unchecked(i as u32 + 1)).unwrap();
            ldm.write(format!("m{}", i), &v).unwrap();
        }
        ldm.save().unwrap();
        let total = Compiler::compile(cs).unwrap().script.len();
        println!(
            "LDM {:>2} × M31 write  = {:>6} B   (per op: {:>5.1} B over baseline)",
            n,
            total,
            (total as f64 - base as f64) / n as f64
        );
    }

    // N writes of a QM31
    for n in [1usize, 4, 16] {
        let cs = ConstraintSystem::new_ref();
        let mut ldm = LDM::new();
        ldm.init(&cs).unwrap();
        for i in 0..n {
            let v =
                QM31Var::new_constant(&cs, QM31::from_u32_unchecked(i as u32, 0, 0, 0)).unwrap();
            ldm.write(format!("q{}", i), &v).unwrap();
        }
        ldm.save().unwrap();
        let total = Compiler::compile(cs).unwrap().script.len();
        println!(
            "LDM {:>2} × QM31 write = {:>6} B   (per op: {:>5.1} B over baseline)",
            n,
            total,
            (total as f64 - base as f64) / n as f64
        );
    }

    // N reads of an M31 (write in one cs, read in the next)
    for n in [1usize, 4, 16] {
        let mut ldm = LDM::new();

        // script A: write n M31 vars
        let cs_a = ConstraintSystem::new_ref();
        ldm.init(&cs_a).unwrap();
        for i in 0..n {
            let v = M31Var::new_constant(&cs_a, M31::from_u32_unchecked(i as u32 + 1)).unwrap();
            ldm.write(format!("m{}", i), &v).unwrap();
        }
        ldm.save().unwrap();
        let _ = Compiler::compile(cs_a).unwrap();

        // script B: read them back
        let cs_b = ConstraintSystem::new_ref();
        ldm.init(&cs_b).unwrap();
        for i in 0..n {
            let _: M31Var = ldm.read(format!("m{}", i)).unwrap();
        }
        ldm.save().unwrap();
        let total = Compiler::compile(cs_b).unwrap().script.len();
        println!(
            "LDM {:>2} × M31 read   = {:>6} B   (per op: {:>5.1} B over baseline)",
            n,
            total,
            (total as f64 - base as f64) / n as f64
        );
    }

    // N reads of a QM31
    for n in [1usize, 4, 16] {
        let mut ldm = LDM::new();

        let cs_a = ConstraintSystem::new_ref();
        ldm.init(&cs_a).unwrap();
        for i in 0..n {
            let v =
                QM31Var::new_constant(&cs_a, QM31::from_u32_unchecked(i as u32, 0, 0, 0)).unwrap();
            ldm.write(format!("q{}", i), &v).unwrap();
        }
        ldm.save().unwrap();
        let _ = Compiler::compile(cs_a).unwrap();

        let cs_b = ConstraintSystem::new_ref();
        ldm.init(&cs_b).unwrap();
        for i in 0..n {
            let _: QM31Var = ldm.read(format!("q{}", i)).unwrap();
        }
        ldm.save().unwrap();
        let total = Compiler::compile(cs_b).unwrap().script.len();
        println!(
            "LDM {:>2} × QM31 read  = {:>6} B   (per op: {:>5.1} B over baseline)",
            n,
            total,
            (total as f64 - base as f64) / n as f64
        );
    }
}
