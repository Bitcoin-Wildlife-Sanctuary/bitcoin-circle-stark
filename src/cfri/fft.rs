use crate::cfri::{
    circle::CirclePoint,
    fields::{Field, M31},
    utils::bit_reverse_index,
};

// pub fn butterfly<F: Field>(v0: &mut F, v1: &mut F, twid: F) {
//     let tmp = *v1 * twid;
//     *v1 = *v0 + (-tmp);
//     *v0 = *v0 + tmp;
// }

pub fn ibutterfly<F: Field>(v0: &mut F, v1: &mut F, itwid: F) {
    let tmp = *v0;
    *v0 = tmp + *v1;
    *v1 = (tmp + (-*v1)) * itwid;
}

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

// pub fn ifft(values: &mut [QM31], twiddles: &[Vec<M31>]) {
//     // assert_eq!(values.len().ilog2() as usize, twiddles.len());
//     for (i, layer_twiddles) in twiddles.iter().enumerate() {
//         let step = 1 << i;
//         for j in (0..values.len()).step_by(step * 2) {
//             for k in 0..step {
//                 let mut v0 = values[j + k];
//                 let mut v1 = values[j + k + step];
//                 ibutterfly(
//                     &mut v0,
//                     &mut v1,
//                     layer_twiddles[j >> (i + 1)].inverse().into(),
//                 );
//                 values[j + k] = v0;
//                 values[j + k + step] = v1;
//             }
//         }
//     }
// }

// pub fn fft(values: &mut [QM31]) {
//     let logn = values.len().ilog2() as usize;
//     let twiddles = get_twiddles(logn);
//     for i in (0..logn).rev() {
//         let step = 1 << i;
//         for j in (0..values.len()).step_by(step * 2) {
//             for k in 0..step {
//                 let mut v0 = values[j + k];
//                 let mut v1 = values[j + k + step];
//                 butterfly(&mut v0, &mut v1, twiddles[i][k].into());
//                 values[j + k] = v0;
//                 values[j + k + step] = v1;
//             }
//         }
//     }
// }
