use crate::fibonacci::bitcoin_script::fiat_shamir::FibonacciFiatShamirGadget;
use crate::fibonacci::bitcoin_script::fold::FibonacciPerQueryFoldGadget;
use crate::fibonacci::bitcoin_script::prepare::FibonacciPrepareGadget;
use crate::fibonacci::bitcoin_script::quotients::FibonacciPerQueryQuotientGadget;
use crate::fibonacci::fiat_shamir::FiatShamirHints;
use crate::fibonacci::fold::PerQueryFoldHints;
use crate::fibonacci::prepare::PrepareHints;
use crate::fibonacci::quotients::PerQueryQuotientHint;
use crate::fibonacci::FIB_LOG_SIZE;
use crate::treepp::*;
use crate::utils::{clean_stack, hash};
use crate::OP_HINT;
use bitcoin_scriptexec::utils::scriptint_vec;
use covenants_gadgets::utils::stack_hash::StackHash;
use covenants_gadgets::CovenantProgram;
use sha2::digest::Update;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use stwo_prover::core::channel::{BWSSha256Channel, Channel};
use stwo_prover::core::fields::{
    m31::{BaseField, M31},
    IntoSlice,
};
use stwo_prover::core::prover::N_QUERIES;
use stwo_prover::core::vcs::{bws_sha256_hash::BWSSha256Hasher, hasher::Hasher};

/// The state of the Fibonacci split program.
#[derive(Clone, Debug)]
pub struct FibonacciSplitState {
    /// The program counter.
    pub pc: usize,
    /// The hash of the stack.
    pub stack_hash: Vec<u8>,
    /// The stack from the execution.
    pub stack: Vec<Vec<u8>>,
}

impl From<FibonacciSplitState> for Script {
    fn from(v: FibonacciSplitState) -> Self {
        script! {
            { v.pc }
            { v.stack_hash }
        }
    }
}

/// An enum of the input to the Fibonacci split program.
#[derive(Clone)]
pub enum FibonacciSplitInput {
    /// Hints for Fiat-Shamir
    FiatShamir(Box<FiatShamirHints>),
    /// Hints for prepare
    Prepare(Vec<Vec<u8>>, PrepareHints),
    /// Hints for per-query quotient and folding
    PerQuery(Vec<Vec<u8>>, PerQueryQuotientHint, PerQueryFoldHints),
    /// Dummy hints for reset
    Reset,
}

impl From<FibonacciSplitInput> for Script {
    fn from(v: FibonacciSplitInput) -> Self {
        match v {
            FibonacciSplitInput::FiatShamir(h) => script! {
                { *h }
            },
            FibonacciSplitInput::Prepare(v, h) => script! {
                for elem in v {
                    { elem }
                }
                { h }
            },
            FibonacciSplitInput::PerQuery(v, h1, h2) => script! {
                for elem in v {
                    { elem }
                }
                { h1 }
                { h2 }
            },
            FibonacciSplitInput::Reset => script! {},
        }
    }
}

/// The Fibonacci split program.
pub struct FibonacciSplitProgram;

impl CovenantProgram for FibonacciSplitProgram {
    type State = FibonacciSplitState;
    type Input = FibonacciSplitInput;
    const CACHE_NAME: &'static str = "FIBONACCI";

    fn new() -> Self::State {
        FibonacciSplitState {
            pc: 0,
            stack_hash: vec![0u8; 32],
            stack: vec![],
        }
    }

    fn get_hash(state: &Self::State) -> Vec<u8> {
        assert_eq!(state.stack_hash.len(), 32);
        let mut sha256 = Sha256::new();
        Update::update(&mut sha256, &scriptint_vec(state.pc as i64));
        Update::update(&mut sha256, &state.stack_hash);
        sha256.finalize().to_vec()
    }

    fn get_all_scripts() -> BTreeMap<usize, Script> {
        let channel = BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[
            M31::reduce(443693538),
        ])));

        let mut map = BTreeMap::new();
        map.insert(
            0,
            script! {
                // input:
                // - old pc
                // - old stack hash
                // - new pc
                // - new stack hash

                OP_SWAP 1 OP_EQUALVERIFY
                OP_ROT 0 OP_EQUALVERIFY
                OP_SWAP { vec![0u8; 32] } OP_EQUALVERIFY

                // stack:
                // - new stack hash
                OP_TOALTSTACK

                // Run the Fiat-Shamir gadget
                { FibonacciFiatShamirGadget::run(&channel) }

                // expected output:
                // - trace oods values (3 * 4 = 12)
                // - composition odds raw values (4 * 4 = 16)
                // - random_coeff2 (4)
                // - circle_poly_alpha (4)
                // - (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
                // - last layer (4)
                // - queries (N_QUERIES)
                // - trace queries (2 * N_QUERIES)
                // - composition queries (8 * N_QUERIES)
                // - masked points (3 * 8 = 24)
                // - oods point (8)
                OP_DEPTH
                { 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 + 16 + 12 }
                OP_EQUALVERIFY

                { StackHash::hash_drop(8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 + 16 + 12) }
                OP_FROMALTSTACK OP_EQUALVERIFY
                OP_TRUE
            }
        );
        map.insert(
            1,
            script! {
                // input:
                // - old pc
                // - old stack hash
                // - new pc
                // - new stack hash

                OP_SWAP 2 OP_EQUALVERIFY
                OP_ROT 1 OP_EQUALVERIFY

                // stack:
                // - old stack hash
                // - new stack hash
                OP_TOALTSTACK OP_TOALTSTACK

                // previous stack, as the first part of the input:
                // - trace oods values (3 * 4 = 12)
                // - composition odds raw values (4 * 4 = 16)
                // - random_coeff2 (4)
                // - circle_poly_alpha (4)
                // - (commitment, alpha), ..., (commitment, alpha) (1 + 4) * FIB_LOG_SIZE
                // - last layer (4)
                // - queries (N_QUERIES)
                // - trace queries (2 * N_QUERIES)
                // - composition queries (8 * N_QUERIES)
                // - masked points (3 * 8 = 24)
                // - oods point (8)

                { StackHash::hash_from_hint(8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 + 4 + 16 + 12) }
                OP_FROMALTSTACK OP_EQUALVERIFY

                { FibonacciPrepareGadget::run() }

                // expected output:
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

                OP_DEPTH
                { 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 }
                OP_EQUALVERIFY

                { StackHash::hash_drop(24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4) }
                OP_FROMALTSTACK OP_EQUALVERIFY
                OP_TRUE
            }
        );
        for i in 0..7 {
            map.insert(
                i + 2,
                script! {
                    // input:
                    // - old pc
                    // - old stack hash
                    // - new pc
                    // - new stack hash

                    OP_SWAP { i + 3 } OP_EQUALVERIFY
                    OP_ROT { i + 2 } OP_EQUALVERIFY

                    // require old/new stack hash to be the same
                    OP_2DUP OP_EQUALVERIFY

                    // stack:
                    // - old stack hash
                    // - new stack hash
                    OP_TOALTSTACK OP_TOALTSTACK

                    { StackHash::hash_from_hint(24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4) }
                    OP_FROMALTSTACK OP_EQUALVERIFY

                    { FibonacciPerQueryQuotientGadget::run(i) }
                    { FibonacciPerQueryFoldGadget::run(i) }

                    OP_DEPTH
                    { 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 }
                    OP_EQUALVERIFY

                    { clean_stack(24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4) }
                    OP_TRUE
                }
            );
        }
        map.insert(
            9,
            script! {
                // input:
                // - old pc
                // - old stack hash
                // - new pc
                // - new stack hash

                OP_SWAP 0 OP_EQUALVERIFY
                OP_ROT 9 OP_EQUALVERIFY

                // stack:
                // - old stack hash
                // - new stack hash
                { [0u8; 32].to_vec() } OP_EQUALVERIFY

                OP_TOALTSTACK
                { StackHash::hash_from_hint(24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4) }
                OP_FROMALTSTACK OP_EQUALVERIFY

                { FibonacciPerQueryQuotientGadget::run(7) }
                { FibonacciPerQueryFoldGadget::run(7) }

                OP_DEPTH
                { 24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4 }
                OP_EQUALVERIFY

                { clean_stack(24 + 4 + 12 + 16 + 12 + 8 + 24 + (2 + 8 + 1) * N_QUERIES + 4 + (1 + 4) * FIB_LOG_SIZE as usize + 4) }
                OP_TRUE
            }
        );
        map.insert(
            10, // reset
            script! {
                // input:
                // - old pc
                // - old stack hash
                // - new pc
                // - new stack hash

                { [0u8; 32].to_vec() } OP_EQUALVERIFY
                0 OP_EQUALVERIFY
                OP_2DROP
                OP_TRUE
            },
        );
        map
    }

    fn get_common_prefix() -> Script {
        script! {
            // hint:
            // - old_state
            // - new_state
            //
            // input:
            // - old_state_hash
            // - new_state_hash
            //
            // output:
            // - old pc
            // - old stack hash
            // - new pc
            // - new stack hash
            //

            OP_TOALTSTACK OP_TOALTSTACK

            for _ in 0..2 {
                OP_HINT OP_1ADD OP_1SUB OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
                OP_HINT OP_SIZE 32 OP_EQUALVERIFY

                OP_2DUP
                OP_CAT
                hash
                OP_FROMALTSTACK OP_EQUALVERIFY
            }
        }
    }

    fn run(id: usize, old_state: &Self::State, input: &Self::Input) -> anyhow::Result<Self::State> {
        if id == 0 {
            assert_eq!(old_state.pc, 0);
            assert!(matches!(input, Self::Input::FiatShamir(_)));

            let fiat_shamir_hints = match input {
                FibonacciSplitInput::FiatShamir(h) => h,
                _ => unreachable!(),
            };

            let channel = BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[
                M31::reduce(443693538),
            ])));

            let script = script! {
                { FibonacciFiatShamirGadget::run(&channel) }
            };

            let final_stack = get_final_stack(
                script,
                convert_to_witness(script! {
                    { *fiat_shamir_hints.clone() }
                })
                .unwrap(),
            );

            let stack_hash = StackHash::compute(&final_stack);

            Ok(Self::State {
                pc: 1,
                stack_hash,
                stack: final_stack,
            })
        } else if id == 1 {
            assert_eq!(old_state.pc, 1);
            assert!(matches!(input, Self::Input::Prepare(_, _)));

            let (stack, prepare_hints) = match input {
                FibonacciSplitInput::Prepare(s, h) => (s, h),
                _ => unreachable!(),
            };

            let script = script! {
                { FibonacciPrepareGadget::run() }
            };

            let mut witness = convert_to_witness(script! {
                { prepare_hints.clone() }
            })
            .unwrap();
            witness.extend_from_slice(stack);

            let final_stack = get_final_stack(script, witness);

            let stack_hash = StackHash::compute(&final_stack);

            Ok(Self::State {
                pc: 2,
                stack_hash,
                stack: final_stack,
            })
        } else if (2..=9).contains(&id) {
            assert_eq!(old_state.pc, id);
            assert!(matches!(input, Self::Input::PerQuery(_, _, _)));

            if id <= 8 {
                Ok(Self::State {
                    pc: id + 1,
                    stack_hash: old_state.stack_hash.clone(),
                    stack: old_state.stack.to_vec(),
                })
            } else {
                Ok(Self::State {
                    pc: 0,
                    stack_hash: vec![0u8; 32],
                    stack: vec![],
                })
            }
        } else if id == 10 {
            Ok(Self::State {
                pc: 0,
                stack_hash: vec![0u8; 32],
                stack: vec![],
            })
        } else {
            unreachable!()
        }
    }
}

#[cfg(test)]
mod test {
    use crate::fibonacci::fiat_shamir::compute_fiat_shamir_hints;
    use crate::fibonacci::fold::compute_fold_hints;
    use crate::fibonacci::prepare::compute_prepare_hints;
    use crate::fibonacci::quotients::compute_quotients_hints;
    use crate::fibonacci::split::{
        FibonacciSplitInput, FibonacciSplitProgram, FibonacciSplitState,
    };
    use crate::fibonacci::FIB_LOG_SIZE;
    use covenants_gadgets::test::{simulation_test, SimulationInstruction};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::cell::RefCell;
    use std::ops::AddAssign;
    use std::rc::Rc;
    use stwo_prover::core::channel::{BWSSha256Channel, Channel};
    use stwo_prover::core::fields::m31::{BaseField, M31};
    use stwo_prover::core::fields::IntoSlice;
    use stwo_prover::core::prover::prove;
    use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hasher;
    use stwo_prover::core::vcs::hasher::Hasher;
    use stwo_prover::examples::fibonacci::Fibonacci;

    #[test]
    fn test_integration() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

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
        let (fiat_shamir_output, fiat_shamir_hints) =
            compute_fiat_shamir_hints(proof.clone(), channel, &fib.air).unwrap();

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

        let total_fee = Rc::new(RefCell::new(0));
        let mut step = 0;

        let reset = Rc::new(RefCell::new(false));
        let mut reset_times = 0;

        let mut test_generator = |old_state: &FibonacciSplitState| {
            step += 1;

            let should_reset = if *reset.borrow() && step % 5 == 0 {
                prng.gen_bool(0.5)
            } else {
                false
            };

            if should_reset {
                reset_times += 1;
                total_fee.borrow_mut().add_assign(3045);
                Some(SimulationInstruction {
                    program_index: 10,
                    fee: 3045,
                    program_input: FibonacciSplitInput::Reset,
                })
            } else if old_state.pc == 0 {
                total_fee.borrow_mut().add_assign(473977);
                Some(SimulationInstruction {
                    program_index: 0,
                    fee: 473977,
                    program_input: FibonacciSplitInput::FiatShamir(Box::new(
                        fiat_shamir_hints.clone(),
                    )),
                })
            } else if old_state.pc == 1 {
                total_fee.borrow_mut().add_assign(325136);
                Some(SimulationInstruction {
                    program_index: 1,
                    fee: 325136,
                    program_input: FibonacciSplitInput::Prepare(
                        old_state.stack.clone(),
                        prepare_hints.clone(),
                    ),
                })
            } else if old_state.pc >= 2 && old_state.pc <= 9 {
                total_fee.borrow_mut().add_assign(591311);
                let i = old_state.pc - 2;
                Some(SimulationInstruction {
                    program_index: old_state.pc,
                    fee: 591311,
                    program_input: FibonacciSplitInput::PerQuery(
                        old_state.stack.clone(),
                        per_query_quotients_hints[i].clone(),
                        per_query_fold_hints[i].clone(),
                    ),
                })
            } else {
                unimplemented!()
            }
        };

        const TIMES: usize = 10;

        simulation_test::<FibonacciSplitProgram>(TIMES * 10, &mut test_generator);

        println!(
            "Doing {} Fibonacci STARK verification takes {} BTC (with a rate 7 sat/vBytes)",
            TIMES,
            *total_fee.borrow() as f64 / 1000.0 / 1000.0 / 100.0
        );

        *reset.borrow_mut() = true;
        simulation_test::<FibonacciSplitProgram>(TIMES * 5, &mut test_generator);
        println!(
            "Testing reset of the script with a probability of 0.5 every 5 steps. {} resets have happened during {} steps.",
            reset_times,
            TIMES * 5,
        );
    }
}
