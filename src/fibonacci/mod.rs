mod bitcoin_script;
pub use bitcoin_script::*;

use crate::channel::{ChannelWithHint, DrawQM31Hints};
use crate::oods::{OODSHint, OODS};
use crate::treepp::pushable::{Builder, Pushable};
use stwo_prover::core::air::{Air, AirExt};
use stwo_prover::core::channel::BWSSha256Channel;
use stwo_prover::core::circle::CirclePoint;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::pcs::CommitmentSchemeVerifier;
use stwo_prover::core::prover::{StarkProof, VerificationError};
use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hash;

/// All the hints for the verifier (note: proof is also provided as a hint).
pub struct VerifierHints {
    /// Commitments from the proof.
    pub commitments: [BWSSha256Hash; 2],

    /// random_coeff comes from adding `proof.commitments[0]` to the channel.
    pub random_coeff_hint: DrawQM31Hints,

    /// OODS hint.
    pub oods_hint: OODSHint,

    /// Testing purpose: the ending channel digest.
    pub test_only: BWSSha256Hash,
}

impl Pushable for VerifierHints {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        builder = self.commitments[0].bitcoin_script_push(builder);
        builder = self.random_coeff_hint.bitcoin_script_push(builder);
        builder = self.commitments[1].bitcoin_script_push(builder);
        builder = self.oods_hint.bitcoin_script_push(builder);
        builder = self.test_only.bitcoin_script_push(builder);
        builder
    }
}

/// A verifier program that generates hints.
pub fn verify_with_hints(
    proof: StarkProof,
    air: &impl Air,
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

    let _ = random_coeff;
    let _ = oods_point;

    Ok(VerifierHints {
        commitments: [proof.commitments[0], proof.commitments[1]],
        random_coeff_hint,
        oods_hint,
        test_only: channel.digest,
    })
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
