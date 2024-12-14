use crate::dsl::plonk::hints::fiat_shamir::FiatShamirOutput;
use crate::dsl::plonk::hints::prepare::PrepareOutput;
use crate::dsl::plonk::hints::quotients::QuotientsOutput;
use crate::merkle_tree::MerkleTreeTwinProof;
use itertools::Itertools;
use std::collections::{BTreeMap, BTreeSet};
use stwo_prover::core::fft::ibutterfly;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::fri::FriProof;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleHasher;

#[derive(Clone)]
pub struct PerQueryFoldHints {
    /// Merkle proofs for the commitments on intermediate folding results.
    pub twin_proofs: Vec<MerkleTreeTwinProof>,
}

pub fn compute_fold_hints(
    fri_proof: &FriProof<Sha256MerkleHasher>,
    fs_output: &FiatShamirOutput,
    prepare_output: &PrepareOutput,
    quotients_output: &QuotientsOutput,
) -> Vec<PerQueryFoldHints> {
    let mut layers = vec![];

    let num_fri_steps = fri_proof.inner_layers.len();

    let mut queries_and_results = BTreeMap::new();
    for (&queries_parent, &value) in fs_output
        .queries_parents
        .iter()
        .zip_eq(quotients_output.fold_results.iter())
    {
        queries_and_results.insert(queries_parent, value);
    }

    let mut twiddles = vec![BTreeMap::<usize, M31>::new(); num_fri_steps];

    for &queries_parent in fs_output.queries_parents.iter() {
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

    let mut twin_proofs = vec![BTreeMap::<usize, MerkleTreeTwinProof>::new(); num_fri_steps];

    let mut depth = prepare_output.precomputed_merkle_tree.layers.len() - 1;

    for (((layer_twiddles, fri_layer_proof), &folding_alpha), twin_proofs_mut) in twiddles
        .iter()
        .zip_eq(fri_proof.inner_layers.iter())
        .zip_eq(fs_output.fri_layer_alphas.iter())
        .zip_eq(twin_proofs.iter_mut())
    {
        let mut iter = fri_layer_proof.evals_subset.iter();

        let mut queries_parent_sorted = queries_and_results.keys().copied().collect_vec();
        queries_parent_sorted.dedup();
        queries_parent_sorted.sort_unstable();

        for &queries_parent in queries_parent_sorted.iter() {
            let sibling = queries_parent ^ 1;
            queries_and_results
                .entry(sibling)
                .or_insert_with(|| *iter.next().unwrap());
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

        let mut queries = BTreeSet::new();
        let mut values = vec![vec![]; 4];
        for &queries_parent in queries_parent_sorted.iter() {
            queries.insert(queries_parent >> 1);
            let (left, right) = if queries_parent % 2 == 0 {
                (queries_parent, queries_parent ^ 1)
            } else {
                (queries_parent ^ 1, queries_parent)
            };

            let f_p = *queries_and_results.get(&left).unwrap();
            values[0].push(f_p.0 .0);
            values[1].push(f_p.0 .1);
            values[2].push(f_p.1 .0);
            values[3].push(f_p.1 .1);

            let f_neg_p = *queries_and_results.get(&right).unwrap();
            values[0].push(f_neg_p.0 .0);
            values[1].push(f_neg_p.0 .1);
            values[2].push(f_neg_p.1 .0);
            values[3].push(f_neg_p.1 .1);
        }

        let proofs = MerkleTreeTwinProof::from_stwo_proof(
            depth,
            &queries.iter().copied().collect::<Vec<usize>>(),
            &values,
            &fri_layer_proof.decommitment,
        );

        for (&queries_parent, proof) in queries_parent_sorted.iter().zip(proofs.iter()) {
            twin_proofs_mut.insert(queries_parent, proof.clone());
        }

        queries_and_results = new_queries_and_results;
        depth -= 1;
    }

    for (_, &v) in queries_and_results.iter() {
        assert_eq!(v, fs_output.last_layer);
    }

    let mut all_fold_hints = vec![];

    for &queries_parent in fs_output.queries_parents.iter() {
        let mut idx = queries_parent;
        let mut proofs = vec![];

        for layer_twin_proofs in twin_proofs.iter() {
            proofs.push(layer_twin_proofs.get(&idx).unwrap().clone());
            idx >>= 1;
        }

        // test if the proof are correct
        let mut depth = prepare_output.precomputed_merkle_tree.layers.len() - 1;
        let mut idx = queries_parent;

        for (proof, commitment) in proofs.iter().zip(fs_output.fri_layer_commitments.iter()) {
            assert!(proof.verify(commitment, depth, (idx >> 1) << 1));
            depth -= 1;
            idx >>= 1;
        }

        all_fold_hints.push(PerQueryFoldHints {
            twin_proofs: proofs,
        });
    }

    all_fold_hints
}
