use crate::fibonacci::fiat_shamir::FSOutput;
use crate::fibonacci::prepare::PrepareOutput;
use crate::fibonacci::quotients::QuotientsOutput;
use crate::merkle_tree::MerkleTreeTwinProof;
use itertools::Itertools;
use std::collections::BTreeMap;
use stwo_prover::core::fft::ibutterfly;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::fri::FriProof;
use stwo_prover::core::vcs::bws_sha256_merkle::BWSSha256MerkleHasher;

pub struct PerQueryFoldHints {
    pub twin_proofs: Vec<MerkleTreeTwinProof>,
}

pub fn compute_fold_hints(
    fri_proof: &FriProof<BWSSha256MerkleHasher>,
    fs_output: &FSOutput,
    prepare_output: &PrepareOutput,
    quotients_output: &QuotientsOutput,
) -> Vec<PerQueryFoldHints> {
    let mut layers = vec![];

    let num_fri_steps = fri_proof.inner_layers.len();

    let mut queries_and_results = BTreeMap::new();
    for (&queries_parent, &value) in prepare_output
        .queries_parents
        .iter()
        .zip_eq(quotients_output.fold_results.iter())
    {
        queries_and_results.insert(queries_parent, value);
    }

    let mut twiddles = vec![BTreeMap::<usize, M31>::new(); num_fri_steps];

    for &queries_parent in prepare_output.queries_parents.iter() {
        let query_result = prepare_output
            .precomputed_merkle_tree
            .query(queries_parent << 1);

        let mut idx = queries_parent;
        for (twiddles_mut, &elem) in twiddles
            .iter_mut()
            .zip(query_result.twiddles_elements.iter().rev().skip(1))
        {
            twiddles_mut.insert(idx, elem);
            idx >>= 1;
        }
    }

    for ((layer_twiddles, fri_layer_proof), &folding_alpha) in twiddles
        .iter()
        .zip_eq(fri_proof.inner_layers.iter())
        .zip_eq(fs_output.fri_input.folding_alphas.iter())
    {
        let mut iter = fri_layer_proof.evals_subset.iter();

        let mut queries_parent_sorted = queries_and_results.keys().copied().collect_vec();
        queries_parent_sorted.dedup();
        queries_parent_sorted.sort_unstable();

        for &queries_parent in queries_parent_sorted.iter() {
            let sibling = queries_parent ^ 1;
            if queries_and_results.get(&sibling).is_none() {
                queries_and_results.insert(sibling, *iter.next().unwrap());
            }
        }
        assert_eq!(iter.next(), None);

        layers.push(queries_and_results.clone());

        let mut new_queries_and_results = BTreeMap::<usize, SecureField>::new();

        for &queries_parent in queries_parent_sorted.iter() {
            let f_p = *queries_and_results.get(&queries_parent).unwrap();
            let f_neg_p = *queries_and_results.get(&(queries_parent ^ 1)).unwrap();
            let itwid = *layer_twiddles.get(&queries_parent).unwrap();

            let (mut f0_px, mut f1_px) = if queries_parent % 2 == 0 {
                (f_p, f_neg_p)
            } else {
                (f_neg_p, f_p)
            };
            ibutterfly(&mut f0_px, &mut f1_px, itwid);

            let res = folding_alpha * f1_px + f0_px;
            new_queries_and_results.insert(queries_parent >> 1, res);
        }

        queries_and_results = new_queries_and_results;
    }

    for (_, &v) in queries_and_results.iter() {
        assert_eq!(v, fs_output.fiat_shamir_hints.last_layer);
    }

    vec![]
}
