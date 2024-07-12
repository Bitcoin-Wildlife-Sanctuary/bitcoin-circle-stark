pub(crate) mod bitcoin_script;

/// Module for Fiat-Shamir.
pub mod fiat_shamir;
/// Module for folding.
pub mod fold;
/// Module for prepare.
pub mod prepare;
/// Module for quotients.
pub mod quotients;

/// The implementation of a verifier split into multiple transactions.
pub mod split;

pub use bitcoin_script::*;
use itertools::Itertools;

use crate::fibonacci::fiat_shamir::{compute_fiat_shamir_hints, FiatShamirHints};
use crate::fibonacci::fold::{compute_fold_hints, PerQueryFoldHints};
use crate::fibonacci::prepare::{compute_prepare_hints, PrepareHints};
use crate::fibonacci::quotients::compute_quotients_hints;
use crate::treepp::pushable::{Builder, Pushable};
use quotients::PerQueryQuotientHint;
use stwo_prover::core::air::Air;
use stwo_prover::core::backend::CpuBackend;
use stwo_prover::core::channel::BWSSha256Channel;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::pcs::TreeVec;
use stwo_prover::core::poly::circle::SecureCirclePoly;
use stwo_prover::core::prover::{InvalidOodsSampleStructure, StarkProof, VerificationError};
use stwo_prover::core::{ColumnVec, ComponentVec};
use stwo_prover::examples::fibonacci::air::FibonacciAir;

/// All the hints for the verifier (note: proof is also provided as a hint).
pub struct VerifierHints {
    /// Fiat-Shamir hints.
    pub fiat_shamir_hints: FiatShamirHints,

    /// Prepare hints.
    pub prepare_hints: PrepareHints,

    /// Per query quotients hints.
    pub per_query_quotients_hints: Vec<PerQueryQuotientHint>,

    /// Per query folding hints.
    pub per_query_fold_hints: Vec<PerQueryFoldHints>,
}

impl Pushable for VerifierHints {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self.fiat_shamir_hints.bitcoin_script_push(builder);
        builder = self.prepare_hints.bitcoin_script_push(builder);

        for (quotients_hint, fold_hint) in self
            .per_query_quotients_hints
            .iter()
            .zip(self.per_query_fold_hints.iter())
        {
            builder = quotients_hint.bitcoin_script_push(builder);
            builder = fold_hint.bitcoin_script_push(builder);
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
    let (fiat_shamir_output, fiat_shamir_hints) =
        compute_fiat_shamir_hints(proof.clone(), channel, air).unwrap();

    let (prepare_output, prepare_hints) =
        compute_prepare_hints(&fiat_shamir_output, &proof).unwrap();

    let (quotients_output, per_query_quotients_hints) =
        compute_quotients_hints(&fiat_shamir_output, &prepare_output);

    let per_query_fold_hints = compute_fold_hints(
        &proof.commitment_scheme_proof.fri_proof,
        &fiat_shamir_output,
        &prepare_output,
        &quotients_output,
    );

    Ok(VerifierHints {
        fiat_shamir_hints,
        prepare_hints,
        per_query_quotients_hints,
        per_query_fold_hints,
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
