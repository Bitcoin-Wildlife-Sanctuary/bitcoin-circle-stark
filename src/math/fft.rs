use crate::utils::bit_reverse_index;
use stwo_prover::core::circle::CirclePointIndex;
use stwo_prover::core::fields::m31::M31;

/// Compute all the twiddle factors.
pub fn get_twiddles(mut logn: usize) -> Vec<Vec<M31>> {
    let mut twiddles = Vec::with_capacity(logn);

    let mut p = CirclePointIndex::subgroup_gen(logn as u32 + 1).to_point();
    let mut step = CirclePointIndex::subgroup_gen(logn as u32 - 1).to_point();

    let mut layer = Vec::with_capacity(1 << logn);
    for i in 0..(1 << (logn - 1)) {
        layer.push((p + step.mul(bit_reverse_index(i, logn - 1) as u128)).y);
    }
    twiddles.push(layer);
    for _ in 0..(logn - 1) {
        logn -= 1;
        let mut layer = Vec::with_capacity(1 << logn);
        for i in 0..(1 << (logn - 1)) {
            layer.push((p + step.mul(bit_reverse_index(i, logn - 1) as u128)).x);
        }
        twiddles.push(layer);
        p = p.double();
        step = step.double();
    }

    twiddles
}
