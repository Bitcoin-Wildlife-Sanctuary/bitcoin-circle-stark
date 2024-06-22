mod bitcoin_script;

pub use bitcoin_script::*;
use itertools::Itertools;
use num_traits::One;
use std::iter::zip;

use crate::air::CompositionHint;
use crate::channel::{ChannelWithHint, DrawHints};
use crate::fri::QueriesWithHint;
use crate::merkle_tree::{MerkleTree, MerkleTreeTwinProof};
use crate::oods::{OODSHint, OODS};
use crate::pow::PoWHint;
use crate::treepp::pushable::{Builder, Pushable};
use stwo_prover::core::air::{Air, AirExt};
use stwo_prover::core::backend::CpuBackend;
use stwo_prover::core::channel::{BWSSha256Channel, Channel};
use stwo_prover::core::circle::{CirclePoint, Coset};
use stwo_prover::core::constraints::complex_conjugate_line_coeffs;
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fri::{
    get_opening_positions, CirclePolyDegreeBound, FriConfig, FriLayerVerifier,
    FriVerificationError, FOLD_STEP,
};
use stwo_prover::core::pcs::quotients::PointSample;
use stwo_prover::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo_prover::core::poly::circle::SecureCirclePoly;
use stwo_prover::core::poly::line::LineDomain;
use stwo_prover::core::proof_of_work::ProofOfWork;
use stwo_prover::core::prover::{
    InvalidOodsSampleStructure, StarkProof, VerificationError, LOG_BLOWUP_FACTOR,
    LOG_LAST_LAYER_DEGREE_BOUND, N_QUERIES, PROOF_OF_WORK_BITS,
};
use stwo_prover::core::queries::Queries;
use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hash;
use stwo_prover::core::{ColumnVec, ComponentVec};
use stwo_prover::examples::fibonacci::air::FibonacciAir;

/// All the hints for the verifier (note: proof is also provided as a hint).
pub struct VerifierHints {
    /// Commitments from the proof.
    pub commitments: [BWSSha256Hash; 2],

    /// random_coeff comes from adding `proof.commitments[0]` to the channel.
    pub random_coeff_hint: DrawHints,

    /// OODS hint.
    pub oods_hint: OODSHint,

    /// trace oods values.
    pub trace_oods_values: [SecureField; 3],

    /// composition odds raw values.
    pub composition_oods_values: [SecureField; 4],

    /// Composition hint.
    pub composition_hint: CompositionHint,

    /// second random_coeff hint
    pub random_coeff_hint2: DrawHints,

    /// circle_poly_alpha hint
    pub circle_poly_alpha_hint: DrawHints,

    /// fri commit and hints for deriving the folding parameter
    pub fri_commitment_and_folding_hints: Vec<(BWSSha256Hash, DrawHints)>,

    /// last layer poly (assuming only one element)
    pub last_layer: QM31,

    /// PoW hint
    pub pow_hint: PoWHint,

    /// Query sampling hints
    pub queries_hints: DrawHints,

    /// Merkle proofs for the trace Merkle tree
    pub merkle_proofs_traces: Vec<MerkleTreeTwinProof>,

    /// Merkle proofs for the composition Merkle tree
    pub merkle_proofs_compositions: Vec<MerkleTreeTwinProof>,

    /// test only: line coeffs
    pub test_only_line_coeffs: Vec<Vec<(SecureField, SecureField, SecureField)>>,
}

impl Pushable for VerifierHints {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        builder = self.commitments[0].bitcoin_script_push(builder);
        builder = self.random_coeff_hint.bitcoin_script_push(builder);
        builder = self.commitments[1].bitcoin_script_push(builder);
        builder = self.oods_hint.bitcoin_script_push(builder);
        for v in self.trace_oods_values.iter() {
            builder = v.bitcoin_script_push(builder);
        }
        for v in self.composition_oods_values.iter() {
            builder = v.bitcoin_script_push(builder);
        }
        builder = self.composition_hint.bitcoin_script_push(builder);
        builder = self.random_coeff_hint2.bitcoin_script_push(builder);
        builder = self.circle_poly_alpha_hint.bitcoin_script_push(builder);
        for (c, h) in self.fri_commitment_and_folding_hints.iter() {
            builder = c.bitcoin_script_push(builder);
            builder = h.bitcoin_script_push(builder);
        }
        builder = self.last_layer.bitcoin_script_push(builder);
        builder = self.pow_hint.bitcoin_script_push(builder);
        builder = self.queries_hints.bitcoin_script_push(builder);
        for proof in self.merkle_proofs_traces.iter() {
            builder = proof.bitcoin_script_push(builder);
        }
        for proof in self.merkle_proofs_compositions.iter() {
            builder = proof.bitcoin_script_push(builder);
        }
        for batch in self.test_only_line_coeffs.iter().rev() {
            for (a, b, c) in batch.iter().rev() {
                builder = b.1.bitcoin_script_push(builder);
                builder = a.1.bitcoin_script_push(builder);
                builder = c.1.bitcoin_script_push(builder);
            }
        }

        builder
    }
}

/// A verifier program that generates hints.
pub fn verify_with_hints(
    proof: StarkProof,
    air: &FibonacciAir,
    channel: &mut BWSSha256Channel,
) -> Result<VerifierHints, VerificationError> {
    // Read trace commitment.
    let mut commitment_scheme = CommitmentSchemeVerifier::new();
    commitment_scheme.commit(proof.commitments[0], air.column_log_sizes(), channel);
    let (random_coeff, random_coeff_hint) = channel.draw_felt_and_hints();

    // Read composition polynomial commitment.
    commitment_scheme.commit(
        proof.commitments[1],
        vec![air.composition_log_degree_bound(); 4],
        channel,
    );

    // Draw OODS point.
    let (oods_point, oods_hint) = CirclePoint::<SecureField>::get_random_point_with_hint(channel);

    // Get mask sample points relative to oods point.
    let trace_sample_points = air.mask_points(oods_point);
    let masked_points = trace_sample_points.clone();

    // TODO(spapini): Change when we support multiple interactions.
    // First tree - trace.
    let mut sampled_points = TreeVec::new(vec![trace_sample_points.flatten()]);
    // Second tree - composition polynomial.
    sampled_points.push(vec![vec![oods_point]; 4]);

    // this step is just a reorganization of the data
    assert_eq!(sampled_points.0[0][0][0], masked_points[0][0][0]);
    assert_eq!(sampled_points.0[0][0][1], masked_points[0][0][1]);
    assert_eq!(sampled_points.0[0][0][2], masked_points[0][0][2]);

    assert_eq!(sampled_points.0[1][0][0], oods_point);
    assert_eq!(sampled_points.0[1][1][0], oods_point);
    assert_eq!(sampled_points.0[1][2][0], oods_point);
    assert_eq!(sampled_points.0[1][3][0], oods_point);

    // TODO(spapini): Save clone.
    let (trace_oods_values, composition_oods_value) = sampled_values_to_mask(
        air,
        proof.commitment_scheme_proof.sampled_values.clone(),
    )
    .map_err(|_| {
        VerificationError::InvalidStructure("Unexpected sampled_values structure".to_string())
    })?;

    if composition_oods_value
        != air.eval_composition_polynomial_at_point(oods_point, &trace_oods_values, random_coeff)
    {
        return Err(VerificationError::OodsNotMatching);
    }

    let composition_hint = CompositionHint {
        constraint_eval_quotients_by_mask: vec![
            air.component.boundary_constraint_eval_quotient_by_mask(
                oods_point,
                trace_oods_values[0][0][..1].try_into().unwrap(),
            ),
            air.component.step_constraint_eval_quotient_by_mask(
                oods_point,
                trace_oods_values[0][0][..].try_into().unwrap(),
            ),
        ],
    };

    let sample_values = &proof.commitment_scheme_proof.sampled_values.0;

    channel.mix_felts(
        &proof
            .commitment_scheme_proof
            .sampled_values
            .clone()
            .flatten_cols(),
    );
    let (random_coeff, random_coeff_hint2) = channel.draw_felt_and_hints();

    let bounds = commitment_scheme
        .column_log_sizes()
        .zip_cols(&sampled_points)
        .map_cols(|(log_size, sampled_points)| {
            vec![CirclePolyDegreeBound::new(log_size - LOG_BLOWUP_FACTOR); sampled_points.len()]
        })
        .flatten_cols()
        .into_iter()
        .sorted()
        .rev()
        .dedup()
        .collect_vec();

    // FRI commitment phase on OODS quotients.
    let fri_config = FriConfig::new(LOG_LAST_LAYER_DEGREE_BOUND, LOG_BLOWUP_FACTOR, N_QUERIES);

    // from fri-verifier
    let max_column_bound = bounds[0];
    let _ = max_column_bound.log_degree_bound + fri_config.log_blowup_factor;

    // Circle polynomials can all be folded with the same alpha.
    let (circle_poly_alpha, circle_poly_alpha_hint) = channel.draw_felt_and_hints();

    let mut inner_layers = Vec::new();
    let mut layer_bound = max_column_bound.fold_to_line();
    let mut layer_domain = LineDomain::new(Coset::half_odds(
        layer_bound.log_degree_bound + fri_config.log_blowup_factor,
    ));

    let mut fri_commitment_and_folding_hints = vec![];

    for (layer_index, proof) in proof
        .commitment_scheme_proof
        .fri_proof
        .inner_layers
        .into_iter()
        .enumerate()
    {
        channel.mix_digest(proof.commitment);

        let (folding_alpha, folding_alpha_hint) = channel.draw_felt_and_hints();

        fri_commitment_and_folding_hints.push((proof.commitment, folding_alpha_hint));

        inner_layers.push(FriLayerVerifier {
            degree_bound: layer_bound,
            domain: layer_domain,
            folding_alpha,
            layer_index,
            proof,
        });

        layer_bound = layer_bound
            .fold(FOLD_STEP)
            .ok_or(FriVerificationError::InvalidNumFriLayers)?;
        layer_domain = layer_domain.double();
    }

    if layer_bound.log_degree_bound != fri_config.log_last_layer_degree_bound {
        return Err(VerificationError::Fri(
            FriVerificationError::InvalidNumFriLayers,
        ));
    }

    let last_layer_domain = layer_domain;
    let last_layer_poly = proof.commitment_scheme_proof.fri_proof.last_layer_poly;

    if last_layer_poly.len() > (1 << fri_config.log_last_layer_degree_bound) {
        return Err(VerificationError::Fri(
            FriVerificationError::LastLayerDegreeInvalid,
        ));
    }

    channel.mix_felts(&last_layer_poly);

    let pow_hint = PoWHint::new(
        channel.digest,
        proof.commitment_scheme_proof.proof_of_work.nonce,
        PROOF_OF_WORK_BITS,
    );

    // Verify proof of work.
    ProofOfWork::new(PROOF_OF_WORK_BITS)
        .verify(channel, &proof.commitment_scheme_proof.proof_of_work)?;

    let column_log_sizes = bounds
        .iter()
        .dedup()
        .map(|b| b.log_degree_bound + fri_config.log_blowup_factor)
        .collect_vec();

    let (queries, queries_hints) =
        Queries::generate_with_hints(channel, column_log_sizes[0], fri_config.n_queries);
    let fri_query_domains = get_opening_positions(&queries, &column_log_sizes);

    assert_eq!(fri_query_domains.len(), 1);
    let query_domain = fri_query_domains.first_key_value().unwrap();
    assert_eq!(
        *query_domain.0,
        max_column_bound.log_degree_bound + fri_config.log_blowup_factor
    );
    let queries_parents: Vec<usize> = query_domain
        .1
        .iter()
        .map(|subdomain| {
            assert_eq!(subdomain.log_size, 1);
            subdomain.coset_index
        })
        .collect();

    let merkle_proofs_traces = MerkleTreeTwinProof::from_stwo_proof(
        (max_column_bound.log_degree_bound + fri_config.log_blowup_factor) as usize,
        &queries_parents,
        &proof.commitment_scheme_proof.queried_values[0],
        &proof.commitment_scheme_proof.decommitments[0],
    );
    let merkle_proofs_compositions = MerkleTreeTwinProof::from_stwo_proof(
        (max_column_bound.log_degree_bound + fri_config.log_blowup_factor) as usize,
        &queries_parents,
        &proof.commitment_scheme_proof.queried_values[1],
        &proof.commitment_scheme_proof.decommitments[1],
    );

    for (&query, twin_proof) in queries_parents.iter().zip(merkle_proofs_traces.iter()) {
        assert!(MerkleTree::verify_twin(
            &proof.commitments[0],
            (max_column_bound.log_degree_bound + fri_config.log_blowup_factor) as usize,
            twin_proof,
            query << 1
        ));
    }

    for (&query, twin_proof) in queries_parents
        .iter()
        .zip(merkle_proofs_compositions.iter())
    {
        assert!(MerkleTree::verify_twin(
            &proof.commitments[1],
            (max_column_bound.log_degree_bound + fri_config.log_blowup_factor) as usize,
            twin_proof,
            query << 1
        ));
    }

    let column_size: Vec<u32> = commitment_scheme
        .column_log_sizes()
        .flatten()
        .into_iter()
        .dedup()
        .collect();
    assert_eq!(column_size.len(), 1);
    assert_eq!(
        column_size[0],
        max_column_bound.log_degree_bound + fri_config.log_blowup_factor
    );

    // trace polynomials are evaluated on oods, oods+1, oods+2
    assert_eq!(proof.commitment_scheme_proof.sampled_values.0[0].len(), 1);
    assert_eq!(
        proof.commitment_scheme_proof.sampled_values.0[0][0].len(),
        3
    );

    // composition polynomials are evaluated on oods 4 times
    assert_eq!(proof.commitment_scheme_proof.sampled_values.0[1].len(), 4);
    assert_eq!(
        proof.commitment_scheme_proof.sampled_values.0[1][0].len(),
        1
    );

    // construct the list of samples
    // Answer FRI queries.
    let samples = sampled_points
        .zip_cols(&proof.commitment_scheme_proof.sampled_values)
        .map_cols(|(sampled_points, sampled_values)| {
            zip(sampled_points, sampled_values)
                .map(|(point, &value)| PointSample { point, value })
                .collect_vec()
        })
        .flatten();

    let expected: Vec<Vec<(SecureField, SecureField, SecureField)>> = {
        samples
            .iter()
            .map(|sample_batch| {
                sample_batch
                    .iter()
                    .map(|sample| complex_conjugate_line_coeffs(&sample, SecureField::one()))
                    .collect()
            })
            .collect()
    };

    let _ = last_layer_domain;
    let _ = circle_poly_alpha;
    let _ = random_coeff;

    Ok(VerifierHints {
        commitments: [proof.commitments[0], proof.commitments[1]],
        random_coeff_hint,
        oods_hint,
        trace_oods_values: [
            sample_values[0][0][0],
            sample_values[0][0][1],
            sample_values[0][0][2],
        ],
        composition_oods_values: [
            sample_values[1][0][0],
            sample_values[1][1][0],
            sample_values[1][2][0],
            sample_values[1][3][0],
        ],
        composition_hint,
        random_coeff_hint2,
        circle_poly_alpha_hint,
        fri_commitment_and_folding_hints,
        last_layer: last_layer_poly.to_vec()[0],
        pow_hint,
        queries_hints,
        merkle_proofs_traces,
        merkle_proofs_compositions,
        test_only_line_coeffs: expected,
    })
}

fn sampled_values_to_mask(
    air: &impl Air,
    mut sampled_values: TreeVec<ColumnVec<Vec<SecureField>>>,
) -> Result<(ComponentVec<Vec<SecureField>>, SecureField), InvalidOodsSampleStructure> {
    let composition_partial_sampled_values =
        sampled_values.pop().ok_or(InvalidOodsSampleStructure)?;
    let composition_oods_value = SecureCirclePoly::<CpuBackend>::eval_from_partial_evals(
        composition_partial_sampled_values
            .iter()
            .flatten()
            .cloned()
            .collect_vec()
            .try_into()
            .map_err(|_| InvalidOodsSampleStructure)?,
    );

    // Retrieve sampled mask values for each component.
    let flat_trace_values = &mut sampled_values
        .pop()
        .ok_or(InvalidOodsSampleStructure)?
        .into_iter();
    let trace_oods_values = ComponentVec(
        air.components()
            .iter()
            .map(|c| {
                flat_trace_values
                    .take(c.mask_points(CirclePoint::zero()).len())
                    .collect_vec()
            })
            .collect(),
    );

    Ok((trace_oods_values, composition_oods_value))
}

#[cfg(test)]
mod test {
    use stwo_prover::core::channel::{BWSSha256Channel, Channel};
    use stwo_prover::core::fields::m31::{BaseField, M31};
    use stwo_prover::core::fields::IntoSlice;
    use stwo_prover::core::prover::{prove, verify};
    use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hasher;
    use stwo_prover::core::vcs::hasher::Hasher;
    use stwo_prover::examples::fibonacci::Fibonacci;

    #[test]
    fn test_fib_prove() {
        const FIB_LOG_SIZE: u32 = 5;
        let fib = Fibonacci::new(FIB_LOG_SIZE, M31::reduce(443693538));

        let trace = fib.get_trace();
        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        let proof = prove(&fib.air, channel, vec![trace]).unwrap();

        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        verify(proof, &fib.air, channel).unwrap()
    }
}
