use crate::air::AirGadget;
use crate::channel::Sha256ChannelGadget;
use crate::circle::CirclePointGadget;
use crate::fibonacci::bitcoin_script::composition::FibonacciCompositionGadget;
use crate::oods::OODSGadget;
use crate::pow::PowGadget;
use crate::{treepp::*, OP_HINT};
use rust_bitcoin_m31::{qm31_copy, qm31_drop, qm31_dup, qm31_equalverify, qm31_from_bottom};
use stwo_prover::core::channel::BWSSha256Channel;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::prover::{LOG_BLOWUP_FACTOR, N_QUERIES, PROOF_OF_WORK_BITS};

mod composition;

const FIB_LOG_SIZE: u32 = 5;

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
            { CirclePointGadget::dup() }

            // mask the points
            { AirGadget::shifted_mask_points(&vec![vec![0, 1, 2]], &[CanonicCoset::new(FIB_LOG_SIZE)]) }

            // pull trace oods values from the hint
            for _ in 0..3 {
                qm31_from_bottom
            }

            // pull the composition oods raw values from the hint
            for _ in 0..4 {
                qm31_from_bottom
            }

            // stack:
            //    c1, random_coeff (4), c2, channel_digest, oods point (8),
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)

            // update the digest with all the trace oods values and composition odds raw values

            60 OP_ROLL OP_TOALTSTACK
            { qm31_copy(6) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(5) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(4) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(3) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(2) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(1) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK
            { qm31_copy(0) } OP_FROMALTSTACK { Sha256ChannelGadget::mix_felt() } OP_TOALTSTACK

            // stack:
            //    c1, random_coeff (4), c2, oods point (8),
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //
            // altstack:
            //    channel_digest

            { qm31_copy(3) }
            { qm31_copy(3) }
            { qm31_copy(3) }
            { qm31_copy(3) }
            { AirGadget::eval_from_partial_evals() }

            // stack:
            //    c1, random_coeff (4), c2, oods point (8),
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    composition odds value (4)
            //
            // altstack:
            //    channel_digest

            64 OP_ROLL OP_TOALTSTACK
            { qm31_copy(16) }
            { qm31_copy(8) }
            { qm31_copy(8) }
            { qm31_copy(8) }
            { qm31_copy(19) }
            { qm31_copy(19) }

            // stack:
            //    c1, random_coeff (4), oods point (8),
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    composition odds value (4)
            //
            //    random_coeff (4)
            //    trace oods values (3 * 4 = 12)
            //    oods point (8)
            //
            // altstack:
            //    channel_digest, c2

            { FibonacciCompositionGadget::eval_composition_polynomial_at_point(FIB_LOG_SIZE, M31::from_u32_unchecked(443693538)) }

            qm31_equalverify

            OP_FROMALTSTACK OP_FROMALTSTACK

            { Sha256ChannelGadget::draw_felt_with_hint() }

            4 OP_ROLL { Sha256ChannelGadget::draw_felt_with_hint() }
            4 OP_ROLL

            // stack:
            //    c1, random_coeff (4), oods point (8),
            //    masked points (3 * 8 = 24)
            //    trace oods values (3 * 4 = 12)
            //    composition odds raw values (4 * 4 = 16)
            //    c2
            //    random_coeff2 (4)
            //    circle_poly_alpha (4)
            //    channel_digest

            for _ in 0..FIB_LOG_SIZE {
                OP_HINT OP_DUP OP_ROT { Sha256ChannelGadget::mix_digest() }
                { Sha256ChannelGadget::draw_felt_with_hint() }
                4 OP_ROLL
            }

            qm31_from_bottom
            qm31_dup
            8 OP_ROLL
            { Sha256ChannelGadget::mix_felt() }

            { PowGadget::verify_pow(PROOF_OF_WORK_BITS) }

            { Sha256ChannelGadget::draw_numbers_with_hint(N_QUERIES, (FIB_LOG_SIZE + LOG_BLOWUP_FACTOR + 1) as usize) }

            { N_QUERIES } OP_ROLL
            OP_HINT OP_EQUALVERIFY

            // test-only: clean up the stack
            for _ in 0..N_QUERIES {
                OP_DROP // drop the queries (out of order)
            }
            qm31_drop // drop the last layer eval
            for _ in 0..FIB_LOG_SIZE {
                qm31_drop // drop the derived folding_alpha
                OP_DROP // drop the commitment
            }
            qm31_drop // drop circle_poly_alpha
            qm31_drop // drop random_coeff2
            OP_DROP // drop c2
            for _ in 0..(3 + 4) {
                qm31_drop // drop trace oods values and composition oods raw values
            }
            for _ in 0..3 {
                { CirclePointGadget::drop() } // drop masked points
            }
            { CirclePointGadget::drop() } // drop oods point
            qm31_drop // drop random_coeff
            OP_DROP // drop c1
        }
    }
}

#[cfg(test)]
mod test {
    use crate::fibonacci::bitcoin_script::FIB_LOG_SIZE;
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
