use itertools::Itertools;
use stwo_prover::core::air::{Air, AirExt, AirProver, AirProverExt};
use stwo_prover::core::backend::{Backend, CpuBackend};
use stwo_prover::core::channel::{Blake2sChannel, Channel};
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::m31::BaseField;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::pcs::{CommitmentSchemeProver, CommitmentSchemeVerifier, TreeVec};
use stwo_prover::core::poly::circle::{
    CanonicCoset, CircleEvaluation, SecureCirclePoly, MAX_CIRCLE_DOMAIN_LOG_SIZE,
};
use stwo_prover::core::poly::BitReversedOrder;
use stwo_prover::core::prover::{
    InvalidOodsSampleStructure, ProvingError, StarkProof, VerificationError, LOG_BLOWUP_FACTOR,
};
use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleHasher;
use stwo_prover::core::vcs::ops::MerkleOps;
use stwo_prover::core::{ColumnVec, ComponentVec};
use tracing::{span, Level};

pub fn prove<B: Backend + MerkleOps<Blake2sMerkleHasher>>(
    air: &impl AirProver<B>,
    channel: &mut Blake2sChannel,
    trace: ColumnVec<CircleEvaluation<B, BaseField, BitReversedOrder>>,
) -> Result<StarkProof, ProvingError> {
    // Check that traces are not too big.
    for (i, trace) in trace.iter().enumerate() {
        if trace.domain.log_size() + LOG_BLOWUP_FACTOR > MAX_CIRCLE_DOMAIN_LOG_SIZE {
            return Err(ProvingError::MaxTraceDegreeExceeded {
                trace_index: i,
                degree: trace.domain.log_size(),
            });
        }
    }

    // Check that the composition polynomial is not too big.
    let composition_polynomial_log_degree_bound = air.composition_log_degree_bound();
    if composition_polynomial_log_degree_bound + LOG_BLOWUP_FACTOR > MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(ProvingError::MaxCompositionDegreeExceeded {
            degree: composition_polynomial_log_degree_bound,
        });
    }

    let span = span!(Level::INFO, "Precompute twiddle").entered();
    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(air.composition_log_degree_bound() + LOG_BLOWUP_FACTOR)
            .circle_domain()
            .half_coset,
    );
    span.exit();

    // Evaluate and commit on trace.
    // TODO(spapini): Commit on trace outside.
    let span = span!(Level::INFO, "Trace interpolation").entered();
    let trace_polys = trace
        .into_iter()
        .map(|poly| poly.interpolate_with_twiddles(&twiddles))
        .collect();
    span.exit();

    let mut commitment_scheme = CommitmentSchemeProver::new(LOG_BLOWUP_FACTOR);
    let span = span!(Level::INFO, "Trace commitment").entered();
    commitment_scheme.commit(trace_polys, channel, &twiddles);
    span.exit();

    // Evaluate and commit on composition polynomial.
    let random_coeff = channel.draw_felt();

    let span = span!(Level::INFO, "Composition generation").entered();
    let composition_polynomial_poly = air.compute_composition_polynomial(
        random_coeff,
        &air.component_traces(
            &commitment_scheme.trees[0].polynomials,
            &commitment_scheme.trees[0].evaluations,
        ),
    );
    span.exit();

    let span = span!(Level::INFO, "Composition commitment").entered();
    commitment_scheme.commit(composition_polynomial_poly.to_vec(), channel, &twiddles);
    span.exit();

    // Draw OODS point.
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    // Get mask sample points relative to oods point.
    let sample_points = air.mask_points(oods_point);

    // TODO(spapini): Change when we support multiple interactions.
    // First tree - trace.
    let mut sample_points = TreeVec::new(vec![sample_points.flatten()]);
    // Second tree - composition polynomial.
    sample_points.push(vec![vec![oods_point]; 4]);

    // Prove the trace and composition OODS values, and retrieve them.
    let commitment_scheme_proof = commitment_scheme.prove_values(sample_points, channel, &twiddles);

    // Evaluate composition polynomial at OODS point and check that it matches the trace OODS
    // values. This is a sanity check.
    // TODO(spapini): Save clone.
    let (trace_oods_values, composition_oods_value) =
        sampled_values_to_mask(air, commitment_scheme_proof.sampled_values.clone()).unwrap();

    if composition_oods_value
        != air.eval_composition_polynomial_at_point(oods_point, &trace_oods_values, random_coeff)
    {
        return Err(ProvingError::ConstraintsNotSatisfied);
    }

    Ok(StarkProof {
        commitments: commitment_scheme.roots(),
        commitment_scheme_proof,
    })
}

pub fn verify(
    proof: StarkProof,
    air: &impl Air,
    channel: &mut Blake2sChannel,
) -> Result<(), VerificationError> {
    // Read trace commitment.
    let mut commitment_scheme = CommitmentSchemeVerifier::new();
    commitment_scheme.commit(proof.commitments[0], air.column_log_sizes(), channel);
    let random_coeff = channel.draw_felt();

    // Read composition polynomial commitment.
    commitment_scheme.commit(
        proof.commitments[1],
        vec![air.composition_log_degree_bound(); 4],
        channel,
    );

    // Draw OODS point.
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    // Get mask sample points relative to oods point.
    let trace_sample_points = air.mask_points(oods_point);

    // TODO(spapini): Change when we support multiple interactions.
    // First tree - trace.
    let mut sample_points = TreeVec::new(vec![trace_sample_points.flatten()]);
    // Second tree - composition polynomial.
    sample_points.push(vec![vec![oods_point]; 4]);

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

    commitment_scheme.verify_values(sample_points, proof.commitment_scheme_proof, channel)
}

/// Structures the tree-wise sampled values into component-wise OODS values and a composition
/// polynomial OODS value.
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
