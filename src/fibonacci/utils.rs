use stwo_prover::core::air::AirExt;
use stwo_prover::core::channel::{BWSSha256Channel, Channel};
use stwo_prover::core::circle::{CirclePoint, Coset};
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fri::{
    CirclePolyDegreeBound, FriConfig, FriLayerVerifier, FriVerificationError, FOLD_STEP,
};
use stwo_prover::core::pcs::{CommitmentSchemeVerifier, TreeVec};
use stwo_prover::core::poly::line::LineDomain;
use stwo_prover::core::proof_of_work::ProofOfWork;
use stwo_prover::core::prover::{
    StarkProof, VerificationError, LOG_BLOWUP_FACTOR, LOG_LAST_LAYER_DEGREE_BOUND, N_QUERIES,
    PROOF_OF_WORK_BITS,
};
use stwo_prover::core::queries::Queries;
use stwo_prover::core::ColumnVec;
use stwo_prover::examples::fibonacci::air::FibonacciAir;

use crate::air::CompositionHint;
use crate::channel::ChannelWithHint;
use crate::fibonacci::fiat_shamir::FiatShamirHints;
use crate::fibonacci::sampled_values_to_mask;
use crate::fri::QueriesWithHint;
use crate::oods::OODS;
use crate::pow::PoWHint;
use itertools::Itertools;

pub struct FriInput {
    pub fri_log_blowup_factor: u32,
    pub max_column_log_degree_bound: u32,
    pub column_log_sizes: Vec<u32>,
    pub commitment_scheme_column_log_sizes: TreeVec<ColumnVec<u32>>,
    pub sampled_points: TreeVec<Vec<Vec<CirclePoint<QM31>>>>,
    pub sample_values: Vec<Vec<Vec<QM31>>>,
    pub random_coeff: QM31,
    pub circle_poly_alpha: QM31,
    pub last_layer_domain: LineDomain,
    pub queries: Queries,
}

pub struct FSOutput {
    pub fiat_shamir_hints: FiatShamirHints,
    pub fri_input: FriInput,
}

/// Generate Fiat Shamir hints along with fri inputs
pub fn generate_fs_hints(
    proof: StarkProof,
    channel: &mut BWSSha256Channel,
    air: &FibonacciAir,
) -> Result<FSOutput, VerificationError> {
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
    let (trace_oods_values, composition_oods_value) =
        sampled_values_to_mask(air, proof.commitment_scheme_proof.sampled_values.clone())
            .map_err(|_| {
                VerificationError::InvalidStructure(
                    "Unexpected sampled_values structure".to_string(),
                )
            })
            .unwrap();

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

    let fiat_shamir_hints = FiatShamirHints {
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
    };

    Ok(FSOutput {
        fiat_shamir_hints,
        fri_input: FriInput {
            fri_log_blowup_factor: fri_config.log_blowup_factor,
            max_column_log_degree_bound: max_column_bound.log_degree_bound,
            column_log_sizes,
            commitment_scheme_column_log_sizes: commitment_scheme.column_log_sizes(),
            sampled_points,
            sample_values: sample_values.to_vec(),
            random_coeff,
            circle_poly_alpha,
            last_layer_domain,
            queries,
        },
    })
}
