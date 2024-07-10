use crate::circle::CirclePointGadget;
use crate::fibonacci::bitcoin_script::fiat_shamir::FibonacciFiatShamirGadget;
use crate::fibonacci::bitcoin_script::fold::FibonacciFoldGadget;
use crate::fibonacci::bitcoin_script::prepare::PrepareGadget;
use crate::fibonacci::bitcoin_script::quotients::FibonacciPerQueryQuotientGadget;
use crate::treepp::*;
use rust_bitcoin_m31::qm31_drop;
use stwo_prover::core::channel::BWSSha256Channel;
use stwo_prover::core::prover::N_QUERIES;

mod composition;

mod fiat_shamir;

mod quotients;

mod prepare;

mod fold;

const FIB_LOG_SIZE: u32 = 5;

/// A verifier for the Fibonacci proof.
pub struct FibonacciVerifierGadget;

impl FibonacciVerifierGadget {
    /// Run the verifier in the Bitcoin script.
    pub fn run_verifier(channel: &BWSSha256Channel) -> Script {
        script! {
            // Run the Fiat-Shamir gadget
            { FibonacciFiatShamirGadget::run(channel) }

            // Run prepare gadget
            { PrepareGadget::run() }

            // stack:
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES)
            //    composition queries (8 * N_QUERIES)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)
            //    (a, b), (a, b), (a, b), (a, b) for composition (4 * 2 * 2 = 16)
            //    prepared masked points (3 * 4 = 12)
            //    prepared oods point (4)
            //    coeff^6, coeff^5, ..., coeff (24)

            for i in 0..N_QUERIES {
                { FibonacciPerQueryQuotientGadget::run(i) }
                { FibonacciFoldGadget::run(i) }
            }

            // stack:
            //    circle_poly_alpha (4)
            //    (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
            //    last layer (4)
            //    queries (N_QUERIES)
            //    trace queries (2 * N_QUERIES - 2 * 1)
            //    composition queries (8 * N_QUERIES - 8 * 1)
            //    masked points (3 * 8 = 24)
            //    oods point (8)
            //    (a, b), (a, b), (a, b) for trace (3 * 2 * 2 = 12)
            //    (a, b), (a, b), (a, b), (a, b) for composition (4 * 2 * 2 = 16)
            //    prepared masked points (3 * 4 = 12)
            //    prepared oods point (4)
            //    random_coeff2 (4)

            // test-only: clean up the stack
            for _ in 0..6 {
                qm31_drop
            } // drop coeff^6, coeff^5, ..., coeff
            for _ in 0..16 {
                OP_DROP
            } // drop the prepared points
            for _ in 0..28 {
                OP_DROP
            } // drop the column line coeffs
            { CirclePointGadget::drop() } // drop oods point
            for _ in 0..3 {
                { CirclePointGadget::drop() } // drop masked points
            }
            for _ in 0..N_QUERIES {
                OP_2DROP OP_2DROP OP_2DROP OP_2DROP // drop the queried values for composition
            }
            for _ in 0..N_QUERIES {
                OP_2DROP // drop the queried values for trace
            }
            for _ in 0..N_QUERIES {
                OP_DROP // drop the queries (out of order)
            }
            qm31_drop // drop the last layer eval
            for _ in 0..FIB_LOG_SIZE {
                qm31_drop // drop the derived folding_alpha
                OP_DROP // drop the commitment
            }
            qm31_drop // drop circle_poly_alpha
        }
    }
}

#[cfg(test)]
mod test {
    use crate::fibonacci::bitcoin_script::FIB_LOG_SIZE;
    use crate::fibonacci::{verify_with_hints, FibonacciVerifierGadget};
    use crate::tests_utils::report::report_bitcoin_script_size;
    use crate::treepp::*;
    use stwo_prover::core::channel::{BWSSha256Channel, Channel};
    use stwo_prover::core::fields::m31::{BaseField, M31};
    use stwo_prover::core::fields::IntoSlice;
    use stwo_prover::core::prover::{prove, verify};
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

        {
            let channel =
                &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                    .air
                    .component
                    .claim])));
            verify(proof.clone(), &fib.air, channel).unwrap();
        }

        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        let channel_clone = channel.clone();

        let hint = verify_with_hints(proof, &fib.air, channel).unwrap();

        let witness = script! {
            { hint }
        };

        let script = script! {
            { FibonacciVerifierGadget::run_verifier(&channel_clone) }
            OP_TRUE
        };

        report_bitcoin_script_size("Fibonacci", "verifier", script.len());

        let exec_result = execute_script_with_witness_unlimited_stack(
            script,
            convert_to_witness(witness).unwrap(),
        );
        assert!(exec_result.success);
    }
}
