use crate::dsl::plonk::hints::fiat_shamir::FiatShamirHints;
use crate::dsl::plonk::hints::fold::PerQueryFoldHints;
use crate::dsl::plonk::hints::quotients::PerQueryQuotientHint;
use stwo_prover::core::channel::Sha256Channel;
use stwo_prover::core::pcs::PcsConfig;
use stwo_prover::core::vcs::sha256_merkle::Sha256MerkleChannel;
use stwo_prover::examples::plonk::prove_fibonacci_plonk;

pub const LOG_N_ROWS: u32 = 5;

mod fiat_shamir;
mod fold;
mod prepare;
mod quotients;

pub struct Hints {
    pub fiat_shamir_hints: FiatShamirHints,
    pub per_query_quotients_hints: Vec<PerQueryQuotientHint>,
    pub per_query_fold_hints: Vec<PerQueryFoldHints>,
}

impl Hints {
    pub fn instance() -> Self {
        let config = PcsConfig::default();

        let (plonk_component, proof) =
            prove_fibonacci_plonk::<Sha256MerkleChannel>(LOG_N_ROWS, config);

        let mut channel = Sha256Channel::default();

        let (fiat_shamir_output, fiat_shamir_hints) = fiat_shamir::compute_fiat_shamir_hints(
            proof.clone(),
            &mut channel,
            &plonk_component,
            config,
        )
        .unwrap();

        let prepare_output = prepare::compute_prepare_hints(&fiat_shamir_output, &proof).unwrap();

        let (quotients_output, per_query_quotients_hints) =
            quotients::compute_quotients_hints(&fiat_shamir_output, &prepare_output);

        let per_query_fold_hints = fold::compute_fold_hints(
            &proof.commitment_scheme_proof.fri_proof,
            &fiat_shamir_output,
            &prepare_output,
            &quotients_output,
        );

        Hints {
            fiat_shamir_hints,
            per_query_quotients_hints,
            per_query_fold_hints,
        }
    }
}
