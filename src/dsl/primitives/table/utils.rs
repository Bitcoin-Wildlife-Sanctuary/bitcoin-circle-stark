use crate::treepp::*;
use rand::{Rng, RngCore};
use stwo_prover::core::fields::cm31::CM31;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

pub fn convert_m31_to_limbs(v: M31) -> [u32; 4] {
    let v = v.0;
    [v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >> 24) & 255]
}

pub fn convert_m31_from_limbs(v: &[u32]) -> M31 {
    M31::from_u32_unchecked(v[0] + (v[1] << 8) + (v[2] << 16) + (v[3] << 24))
}

pub fn convert_cm31_to_limbs(cm31: CM31) -> [u32; 8] {
    let real_limbs = convert_m31_to_limbs(cm31.0);
    let imag_limbs = convert_m31_to_limbs(cm31.1);

    [
        real_limbs[0],
        real_limbs[1],
        real_limbs[2],
        real_limbs[3],
        imag_limbs[0],
        imag_limbs[1],
        imag_limbs[2],
        imag_limbs[3],
    ]
}

pub fn rand_m31<R: RngCore>(prng: &mut R) -> M31 {
    M31::from_u32_unchecked(prng.gen_range(0..((1i64 << 31) - 1)) as u32)
}

pub fn rand_cm31<R: RngCore>(prng: &mut R) -> CM31 {
    CM31::from_m31(rand_m31(prng), rand_m31(prng))
}

pub fn rand_qm31<R: RngCore>(prng: &mut R) -> QM31 {
    QM31::from_m31(
        rand_m31(prng),
        rand_m31(prng),
        rand_m31(prng),
        rand_m31(prng),
    )
}

pub fn convert_cm31_from_limbs(v: &([u32; 4], [u32; 4])) -> CM31 {
    let real = convert_m31_from_limbs(&v.0);
    let imag = convert_m31_from_limbs(&v.1);
    CM31::from_m31(real, imag)
}

pub fn check_limb_format() -> Script {
    script! {
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
        OP_DUP 256 OP_LESSTHAN OP_VERIFY
    }
}

#[allow(non_snake_case)]
pub fn OP_256MUL() -> Script {
    #[cfg(feature = "assume-op-cat")]
    script! {
        OP_SIZE OP_NOT OP_NOTIF
        OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_SWAP OP_CAT
        OP_ENDIF
    }
    #[cfg(not(feature = "assume-op-cat"))]
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

#[allow(non_snake_case)]
pub fn OP_HINT() -> Script {
    script! {
        OP_DEPTH OP_1SUB OP_ROLL
    }
}
