use crate::channel::Sha256ChannelGadget;
use crate::oods::OODSGadget;
use crate::{treepp::*, OP_HINT};
use stwo_prover::core::channel::BWSSha256Channel;

mod composition;

/// A verifier for the Fibonacci proof.
pub struct FibonacciVerifierGadget;

impl FibonacciVerifierGadget {
    /// Run the verifier in the Bitcoin script.
    pub fn run_verifier(channel: &BWSSha256Channel) -> Script {
        script! {
            // push the initial channel
            { channel.digest }

            // pull the first commitment and mix it with the channel
            OP_HINT
            OP_DUP OP_ROT
            { Sha256ChannelGadget::mix_digest() }

            // draw random_coeff
            { Sha256ChannelGadget::draw_felt_with_hint() }

            4 OP_ROLL

            // pull the second commitment and mix it with the channel
            OP_HINT
            OP_DUP OP_ROT
            { Sha256ChannelGadget::mix_digest() }

            // draw the OODS point
            { OODSGadget::get_random_point() }

            // stack: c1, random_coeff (4), c2, channel_digest, oods point (8)

            8 OP_ROLL

            // test-only: final channel digest
            OP_HINT OP_EQUALVERIFY

            // test-only: clean up the stack
            OP_2DROP OP_2DROP OP_2DROP OP_2DROP
            OP_DROP OP_2DROP OP_2DROP OP_DROP
        }
    }
}

#[cfg(test)]
mod test {
    use crate::fibonacci::{verify_with_hints, FibonacciVerifierGadget};
    use crate::treepp::*;
    use bitcoin_scriptexec::execute_script;
    use stwo_prover::core::channel::{BWSSha256Channel, Channel};
    use stwo_prover::core::fields::m31::{BaseField, M31};
    use stwo_prover::core::fields::IntoSlice;
    use stwo_prover::core::prover::prove;
    use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hasher;
    use stwo_prover::core::vcs::hasher::Hasher;
    use stwo_prover::examples::fibonacci::Fibonacci;

    #[test]
    fn test_verifier() {
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
        let channel_clone = channel.clone();

        let hint = verify_with_hints(proof, &fib.air, channel).unwrap();

        let script = script! {
            { hint }
            { FibonacciVerifierGadget::run_verifier(&channel_clone) }
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
