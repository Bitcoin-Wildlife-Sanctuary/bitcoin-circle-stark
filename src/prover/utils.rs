use crate::fields::{Field, QM31};

pub fn bit_reverse_index(i: usize, log_size: usize) -> usize {
    if i == 0 {
        return 0;
    }
    i.reverse_bits() >> (usize::BITS as usize - log_size)
}

pub fn permute_eval(evaluation: Vec<QM31>) -> Vec<QM31> {
    let logn = evaluation.len().ilog2() as usize;
    let mut layer = vec![QM31::zero(); evaluation.len()];
    for i in 0..evaluation.len() / 2 {
        layer[bit_reverse_index(i, logn)] = evaluation[i * 2];
        layer[bit_reverse_index(i + evaluation.len() / 2, logn)] =
            evaluation[evaluation.len() - 1 - i * 2];
    }
    layer
}
