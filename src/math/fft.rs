use crate::circle::CirclePoint;
use crate::math::{Field, M31};
use crate::utils::bit_reverse_index;

/// Perform an inverse butterfly (for inverse FFT).
pub fn ibutterfly<F: Field>(v0: &mut F, v1: &mut F, itwid: F) {
    let tmp = *v0;
    *v0 = tmp + *v1;
    *v1 = (tmp + (-*v1)) * itwid;
}

/// Compute all the twiddle factors.
pub fn get_twiddles(mut logn: usize) -> Vec<Vec<M31>> {
    let mut twiddles = Vec::with_capacity(logn);

    let mut p = CirclePoint::subgroup_gen(logn + 1);
    let mut step = CirclePoint::subgroup_gen(logn - 1);

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
