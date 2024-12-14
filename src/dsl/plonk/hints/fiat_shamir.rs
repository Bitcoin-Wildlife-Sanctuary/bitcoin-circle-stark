use crate::dsl::plonk::hints::LOG_N_ROWS;
use crate::fri::QueriesWithHint;
use crate::merkle_tree::MerkleTreeTwinProof;
use crate::pow::PoWHint;
use itertools::{izip, Itertools};
use stwo_prover::constraint_framework::logup::LookupElements;
use stwo_prover::core::air::{Component, Components};
use stwo_prover::core::channel::{Channel, Sha256Channel};
use stwo_prover::core::circle::{CirclePoint, Coset};
use stwo_prover::core::fields::m31::{BaseField, M31};
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::fields::secure_column::SECURE_EXTENSION_DEGREE;
use stwo_prover::core::fri::{
    get_opening_positions, CirclePolyDegreeBound, FriConfig, FriLayerVerifier,
    FriVerificationError, FOLD_STEP,
};
use stwo_prover::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo_prover::core::poly::line::LineDomain;
use stwo_prover::core::prover::{
    StarkProof, VerificationError, LOG_BLOWUP_FACTOR, LOG_LAST_LAYER_DEGREE_BOUND, N_QUERIES,
};
use stwo_prover::core::queries::{Queries, SparseSubCircleDomain};
use stwo_prover::core::vcs::sha256_hash::{Sha256Hash, Sha256Hasher};
use stwo_prover::core::vcs::sha256_merkle::{Sha256MerkleChannel, Sha256MerkleHasher};
use stwo_prover::core::ColumnVec;
use stwo_prover::examples::plonk::PlonkComponent;

pub struct FiatShamirOutput {
    /// log blowup factor
    pub fri_log_blowup_factor: u32,

    /// log degree bound of column
    pub max_column_log_degree_bound: u32,

    /// queries' parent indices.
    pub queries_parents: Vec<usize>,

    /// log sizes of commitment scheme columns
    pub commitment_scheme_column_log_sizes: TreeVec<ColumnVec<u32>>,

    /// trace sample points and odds points
    pub sampled_points: TreeVec<Vec<Vec<CirclePoint<QM31>>>>,

    /// query subcircle domain.
    pub query_subcircle_domain: SparseSubCircleDomain,

    /// queried values on the leaves on the left.
    pub queried_values_left: Vec<Vec<M31>>,

    /// queried values on the leaves on the right.
    pub queried_values_right: Vec<Vec<M31>>,

    /// random coefficient
    pub line_batch_random_coeff: QM31,

    /// alpha
    pub circle_poly_alpha: QM31,

    /// FRI commitments
    pub fri_layer_commitments: Vec<Sha256Hash>,

    /// FRI folding alphas
    pub fri_layer_alphas: Vec<QM31>,

    /// Last layer
    pub last_layer: QM31,
}

pub struct FiatShamirHints {
    /// commitment from the proof, including trace commitment, interaction commitment, constant commitment, and composition commitment
    pub commitments: [Sha256Hash; 4],

    /// trace sample values
    pub trace_oods_values: Vec<SecureField>,

    /// interaction sample values
    pub interaction_oods_values: Vec<SecureField>,

    /// constant sample values
    pub constant_oods_values: Vec<SecureField>,

    /// composition sample values
    pub composition_oods_values: Vec<SecureField>,

    /// FRI commitments
    pub fri_layer_commitments: Vec<Sha256Hash>,

    /// FRI folding alphas
    pub fri_layer_alphas: Vec<QM31>,

    /// Last layer
    pub last_layer: QM31,

    /// PoW hint
    pub pow_hint: PoWHint,

    /// Merkle proofs for the trace Merkle tree.
    pub merkle_proofs_traces: Vec<MerkleTreeTwinProof>,

    /// Merkle proofs for the interactions Merkle tree.
    pub merkle_proofs_interactions: Vec<MerkleTreeTwinProof>,

    /// Merkle proofs for the constant Merkle tree.
    pub merkle_proofs_constants: Vec<MerkleTreeTwinProof>,

    /// Merkle proofs for the composition Merkle tree.
    pub merkle_proofs_compositions: Vec<MerkleTreeTwinProof>,

    /// Claimed sum divided by the range
    pub claimed_sum_divided: SecureField,
}

/// Generate Fiat Shamir hints along with fri inputs
pub fn compute_fiat_shamir_hints(
    proof: StarkProof<Sha256MerkleHasher>,
    channel: &mut Sha256Channel,
    component: &PlonkComponent,
    config: PcsConfig,
) -> Result<(FiatShamirOutput, FiatShamirHints), VerificationError> {
    let components = Components([component as &dyn Component].to_vec());
    let mut commitment_scheme: CommitmentSchemeVerifier<Sha256MerkleChannel> =
        CommitmentSchemeVerifier::new(config);

    let max_degree = components.composition_log_degree_bound();
    let sizes = TreeVec::new(vec![
        vec![max_degree; 4],
        vec![max_degree; 8],
        vec![max_degree; 4],
    ]);

    // step 1: absorb trace commitment, squeeze lookup elements
    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    let lookup_elements = LookupElements::<2>::draw(channel);
    assert_eq!(lookup_elements, component.lookup_elements);

    // step 2: absorb interaction commitment and constant commitment, squeeze random coefficient for composition folding
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
    commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);
    let _ = channel.draw_felt();

    // step 3: absorb composition commitment, squeeze oods point
    commitment_scheme.commit(
        *proof.commitments.last().unwrap(),
        &[components.composition_log_degree_bound(); SECURE_EXTENSION_DEGREE],
        channel,
    );
    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);

    // step 4: draw fri folding coefficient with all oods values
    channel.mix_felts(
        &proof
            .commitment_scheme_proof
            .sampled_values
            .clone()
            .flatten_cols(),
    );

    let line_batch_random_coeff = channel.draw_felt();
    let fri_fold_random_coeff = channel.draw_felt();

    // step 5: fri layer operator coefficients (intermediate)
    // Get mask sample points relative to oods point.
    let mut sampled_points = components.mask_points(oods_point);
    // Add the composition polynomial mask points.
    sampled_points.push(vec![vec![oods_point]; SECURE_EXTENSION_DEGREE]);

    let bounds = commitment_scheme
        .column_log_sizes()
        .zip_cols(&sampled_points)
        .map_cols(|(log_size, sampled_points)| {
            vec![
                CirclePolyDegreeBound::new(log_size - config.fri_config.log_blowup_factor);
                sampled_points.len()
            ]
        })
        .flatten_cols()
        .into_iter()
        .sorted()
        .rev()
        .dedup()
        .collect_vec();

    let max_column_bound = bounds[0];
    let mut inner_layers = Vec::new();
    let mut layer_bound = max_column_bound.fold_to_line();
    let mut layer_domain = LineDomain::new(Coset::half_odds(
        layer_bound.log_degree_bound + config.fri_config.log_blowup_factor,
    ));
    let mut fri_layer_alphas = vec![];
    let mut fri_layer_commitments = vec![];

    for (layer_index, proof) in proof
        .commitment_scheme_proof
        .fri_proof
        .inner_layers
        .into_iter()
        .enumerate()
    {
        channel.update_digest(Sha256Hasher::concat_and_hash(
            &proof.commitment,
            &channel.digest(),
        ));

        let folding_alpha = channel.draw_felt();
        fri_layer_alphas.push(folding_alpha);
        fri_layer_commitments.push(proof.commitment);

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

    // step 6: fri layer operator coefficient (last layer)
    if layer_bound.log_degree_bound != config.fri_config.log_last_layer_degree_bound {
        return Err(VerificationError::Fri(
            FriVerificationError::InvalidNumFriLayers,
        ));
    }
    let last_layer_poly = proof.commitment_scheme_proof.fri_proof.last_layer_poly;

    assert_eq!(last_layer_poly.len(), 1);
    if last_layer_poly.len() > (1 << config.fri_config.log_last_layer_degree_bound) {
        return Err(VerificationError::Fri(
            FriVerificationError::LastLayerDegreeInvalid,
        ));
    }
    channel.mix_felts(&last_layer_poly);

    // step 7: Verify proof of work.
    let pow_hint = PoWHint::new(
        channel.digest,
        proof.commitment_scheme_proof.proof_of_work,
        config.pow_bits,
    );

    channel.mix_nonce(proof.commitment_scheme_proof.proof_of_work);
    if channel.trailing_zeros() < config.pow_bits {
        return Err(VerificationError::ProofOfWork);
    }

    // step 8. FRI query domains
    let column_log_sizes = bounds
        .iter()
        .dedup()
        .map(|b| b.log_degree_bound + config.fri_config.log_blowup_factor)
        .collect_vec();

    let (queries, _) =
        Queries::generate_with_hints(channel, column_log_sizes[0], config.fri_config.n_queries);

    let fri_query_domains = get_opening_positions(&queries, &column_log_sizes);

    assert_eq!(fri_query_domains.len(), 1);
    let query_domain = fri_query_domains.first_key_value().unwrap();
    assert_eq!(
        *query_domain.0,
        max_column_bound.log_degree_bound + config.fri_config.log_blowup_factor
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
        (max_column_bound.log_degree_bound + config.fri_config.log_blowup_factor) as usize,
        &queries_parents,
        &proof.commitment_scheme_proof.queried_values[0],
        &proof.commitment_scheme_proof.decommitments[0],
    );
    let merkle_proofs_interactions = MerkleTreeTwinProof::from_stwo_proof(
        (max_column_bound.log_degree_bound + config.fri_config.log_blowup_factor) as usize,
        &queries_parents,
        &proof.commitment_scheme_proof.queried_values[1],
        &proof.commitment_scheme_proof.decommitments[1],
    );
    let merkle_proofs_constants = MerkleTreeTwinProof::from_stwo_proof(
        (max_column_bound.log_degree_bound + config.fri_config.log_blowup_factor) as usize,
        &queries_parents,
        &proof.commitment_scheme_proof.queried_values[2],
        &proof.commitment_scheme_proof.decommitments[2],
    );
    let merkle_proofs_compositions = MerkleTreeTwinProof::from_stwo_proof(
        (max_column_bound.log_degree_bound + config.fri_config.log_blowup_factor) as usize,
        &queries_parents,
        &proof.commitment_scheme_proof.queried_values[3],
        &proof.commitment_scheme_proof.decommitments[3],
    );

    for (&query, twin_proof) in queries_parents.iter().zip(merkle_proofs_traces.iter()) {
        assert!(twin_proof.verify(
            &proof.commitments[0],
            (max_column_bound.log_degree_bound + config.fri_config.log_blowup_factor) as usize,
            query << 1
        ));
    }

    for (&query, twin_proof) in queries_parents
        .iter()
        .zip(merkle_proofs_interactions.iter())
    {
        assert!(twin_proof.verify(
            &proof.commitments[1],
            (max_column_bound.log_degree_bound + config.fri_config.log_blowup_factor) as usize,
            query << 1
        ));
    }

    for (&query, twin_proof) in queries_parents.iter().zip(merkle_proofs_constants.iter()) {
        assert!(twin_proof.verify(
            &proof.commitments[2],
            (max_column_bound.log_degree_bound + config.fri_config.log_blowup_factor) as usize,
            query << 1
        ));
    }

    for (&query, twin_proof) in queries_parents
        .iter()
        .zip(merkle_proofs_compositions.iter())
    {
        assert!(twin_proof.verify(
            &proof.commitments[3],
            (max_column_bound.log_degree_bound + config.fri_config.log_blowup_factor) as usize,
            query << 1
        ));
    }

    let mut queried_values_left = vec![];
    let mut queried_values_right = vec![];
    for (trace, interaction_trace, constant_trace, composition_poly) in izip!(
        merkle_proofs_traces.iter(),
        merkle_proofs_interactions.iter(),
        merkle_proofs_constants.iter(),
        merkle_proofs_compositions.iter(),
    ) {
        let mut left_vec = vec![];
        let mut right_vec = vec![];
        for (&left, &right) in izip!(trace.left.iter(), trace.right.iter())
            .chain(izip!(
                interaction_trace.left.iter(),
                interaction_trace.right.iter()
            ))
            .chain(izip!(
                constant_trace.left.iter(),
                constant_trace.right.iter()
            ))
            .chain(izip!(
                composition_poly.left.iter(),
                composition_poly.right.iter()
            ))
        {
            left_vec.push(left);
            right_vec.push(right);
        }
        queried_values_left.push(left_vec);
        queried_values_right.push(right_vec);
    }

    // FRI commitment phase on OODS quotients.
    let fri_config = FriConfig::new(LOG_LAST_LAYER_DEGREE_BOUND, LOG_BLOWUP_FACTOR, N_QUERIES);

    let output = FiatShamirOutput {
        fri_log_blowup_factor: fri_config.log_blowup_factor,
        max_column_log_degree_bound: max_column_bound.log_degree_bound,
        queries_parents,
        commitment_scheme_column_log_sizes: commitment_scheme.column_log_sizes(),
        sampled_points,
        query_subcircle_domain: query_domain.1.clone(),
        queried_values_left,
        queried_values_right,
        line_batch_random_coeff,
        circle_poly_alpha: fri_fold_random_coeff,
        fri_layer_commitments: fri_layer_commitments.clone(),
        fri_layer_alphas: fri_layer_alphas.clone(),
        last_layer: last_layer_poly.to_vec()[0],
    };

    let claimed_sum_divided =
        component.claimed_sum / BaseField::from_u32_unchecked(1 << LOG_N_ROWS);

    let hints = FiatShamirHints {
        commitments: [
            proof.commitments[0],
            proof.commitments[1],
            proof.commitments[2],
            proof.commitments[3],
        ],
        trace_oods_values: proof.commitment_scheme_proof.sampled_values[0]
            .iter()
            .flatten()
            .cloned()
            .collect_vec(),
        interaction_oods_values: proof.commitment_scheme_proof.sampled_values[1]
            .iter()
            .flatten()
            .cloned()
            .collect_vec(),
        constant_oods_values: proof.commitment_scheme_proof.sampled_values[2]
            .iter()
            .flatten()
            .cloned()
            .collect_vec(),
        composition_oods_values: proof.commitment_scheme_proof.sampled_values[3]
            .iter()
            .flatten()
            .cloned()
            .collect_vec(),
        fri_layer_commitments,
        fri_layer_alphas,
        last_layer: last_layer_poly.to_vec()[0],
        pow_hint,
        merkle_proofs_traces,
        merkle_proofs_interactions,
        merkle_proofs_constants,
        merkle_proofs_compositions,
        claimed_sum_divided,
    };

    Ok((output, hints))
}
