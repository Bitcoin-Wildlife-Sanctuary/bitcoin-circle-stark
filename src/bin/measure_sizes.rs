//! Standalone binary that prints the raw Bitcoin-Script byte-sizes of the
//! M31 / CM31 / QM31 multiplication gadgets and related pieces, so we can
//! reason about "what if mul were free" without having to run cargo test.

use bitcoin_circle_stark::dsl::primitives::m31_limbs::m31_to_limbs_gadget;
use bitcoin_circle_stark::dsl::primitives::table::lookup::Lookup8BitGadget;
use bitcoin_circle_stark::dsl::primitives::table::m31::{M31LimbsGadget, M31MultGadget};
use bitcoin_circle_stark::dsl::primitives::table::utils::{check_limb_format, OP_256MUL};
use bitcoin_circle_stark::treepp::*;

fn report(name: &str, s: Script) {
    println!("{:<40} = {:>6} bytes", name, s.len());
}

fn main() {
    // --- primitives ---
    report("check_limb_format", check_limb_format());
    report("OP_256MUL", OP_256MUL());
    report("m31_to_limbs_gadget", m31_to_limbs_gadget());
    report("Lookup8BitGadget::lookup(0)", Lookup8BitGadget::lookup(0));
    report("Lookup8BitGadget::lookup(8)", Lookup8BitGadget::lookup(8));
    report(
        "Lookup8BitGadget::lookup(100)",
        Lookup8BitGadget::lookup(100),
    );

    // --- M31 table-mul building blocks ---
    report("M31LimbsGadget::add_limbs", M31LimbsGadget::add_limbs());
    report(
        "M31LimbsGadget::add_limbs_with_reduction",
        M31LimbsGadget::add_limbs_with_reduction(),
    );
    report(
        "M31MultGadget::compute_c_limbs(0)",
        M31MultGadget::compute_c_limbs(0),
    );
    report(
        "M31MultGadget::compute_c_limbs(8)",
        M31MultGadget::compute_c_limbs(8),
    );
    report("M31MultGadget::reduce", M31MultGadget::reduce());

    // --- Raw (non-table) multiplication from rust-bitcoin-m31 ---
    report("rust_bitcoin_m31::m31_mul", rust_bitcoin_m31::m31_mul());
    report("rust_bitcoin_m31::m31_add", rust_bitcoin_m31::m31_add());
    report("rust_bitcoin_m31::m31_sub", rust_bitcoin_m31::m31_sub());
    report("rust_bitcoin_m31::cm31_mul", rust_bitcoin_m31::cm31_mul());
    report("rust_bitcoin_m31::cm31_add", rust_bitcoin_m31::cm31_add());
    report("rust_bitcoin_m31::cm31_sub", rust_bitcoin_m31::cm31_sub());
    report("rust_bitcoin_m31::qm31_mul", rust_bitcoin_m31::qm31_mul());
    report("rust_bitcoin_m31::qm31_add", rust_bitcoin_m31::qm31_add());
    report("rust_bitcoin_m31::qm31_sub", rust_bitcoin_m31::qm31_sub());
}
