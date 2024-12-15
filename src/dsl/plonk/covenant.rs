use crate::dsl::plonk::hints::Hints;
use crate::treepp::*;
use crate::utils::hash;
use crate::OP_HINT;
use anyhow::Result;
use bitcoin::script::write_scriptint;
use bitcoin_script_dsl::compiler::Compiler;
use bitcoin_script_dsl::constraint_system::Element;
use bitcoin_script_dsl::ldm::LDM;
use bitcoin_scriptexec::utils::scriptint_vec;
use covenants_gadgets::utils::stack_hash::StackHash;
use covenants_gadgets::CovenantProgram;
use sha2::digest::Update;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub type Witness = Vec<Vec<u8>>;

pub struct PlonkVerifierProgram {}

#[derive(Clone)]
pub struct PlonkVerifierInput {
    pub stack: Witness,
    pub hints: Witness,
}

impl From<PlonkVerifierInput> for Script {
    fn from(input: PlonkVerifierInput) -> Script {
        script! {
            for elem in input.stack {
                { elem }
            }
            for elem in input.hints {
                { elem }
            }
        }
    }
}

/// The state of the Plonk split program.
#[derive(Clone, Debug)]
pub struct PlonkVerifierState {
    /// The program counter.
    pub pc: usize,
    /// The hash of the stack.
    pub stack_hash: Vec<u8>,
    /// The stack from the execution.
    pub stack: Vec<Vec<u8>>,
}

impl From<PlonkVerifierState> for Script {
    fn from(v: PlonkVerifierState) -> Self {
        script! {
            { v.pc }
            { v.stack_hash }
        }
    }
}

pub struct PlonkAllInformation {
    pub scripts: Vec<Script>,
    pub witnesses: Vec<Witness>,
    pub outputs: Vec<Witness>,
}

pub static PLONK_ALL_INFORMATION: OnceLock<PlonkAllInformation> = OnceLock::new();

impl PlonkAllInformation {
    pub fn get_input(&self, idx: usize) -> PlonkVerifierInput {
        PlonkVerifierInput {
            stack: if idx == 0 {
                vec![]
            } else {
                self.outputs[idx - 1].clone()
            },
            hints: self.witnesses[idx].clone(),
        }
    }
}

pub fn compute_all_information() -> PlonkAllInformation {
    let mut scripts = vec![];
    let mut witnesses = vec![];

    let hints = Hints::instance();
    let mut ldm = LDM::new();

    let num_to_str = |v: i32| {
        let mut out = [0u8; 8];
        let len = write_scriptint(&mut out, v as i64);
        out[0..len].to_vec()
    };

    let mut outputs = vec![];

    for f in [
        super::part1_fiat_shamir1::generate_cs,
        super::part2_fiat_shamir2_and_constraint_num::generate_cs,
        super::part3_constraint_denom::generate_cs,
        super::part4_pair_vanishing_and_alphas::generate_cs,
        super::part5_column_line_coeffs1::generate_cs,
        super::part6_column_line_coeffs2::generate_cs,
        super::part7_column_line_coeffs3::generate_cs,
    ] {
        let cs = f(&hints, &mut ldm).unwrap();
        let program = Compiler::compile(cs).unwrap();

        scripts.push(program.script);

        let mut witness = vec![];
        for entry in program.hint.iter() {
            match &entry {
                Element::Num(v) => {
                    witness.push(num_to_str(*v));
                }
                Element::Str(v) => {
                    witness.push(v.clone());
                }
            }
        }

        witnesses.push(witness);
        outputs.push(
            convert_to_witness(script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            })
            .unwrap(),
        );
    }

    for query_idx in 0..8 {
        for f in [
            super::per_query_part1_folding::generate_cs,
            super::per_query_part2_num_trace::generate_cs,
            super::per_query_part3_num_constant::generate_cs,
            super::per_query_part4_num_composition::generate_cs,
            super::per_query_part5_num_interaction_shifted::generate_cs,
            super::per_query_part6_num_interaction1::generate_cs,
            super::per_query_part7_num_interaction2::generate_cs,
            super::per_query_part8_last_step::generate_cs,
        ] {
            let dsl = f(&hints, &mut ldm, query_idx).unwrap();
            let program = Compiler::compile(dsl).unwrap();

            scripts.push(program.script);

            let mut witness = vec![];
            for entry in program.hint.iter() {
                match &entry {
                    Element::Num(v) => {
                        witness.push(num_to_str(*v));
                    }
                    Element::Str(v) => {
                        witness.push(v.clone());
                    }
                }
            }

            witnesses.push(witness);

            outputs.push(
                convert_to_witness(script! {
                    { ldm.hash_var.as_ref().unwrap().value.clone() }
                })
                .unwrap(),
            );
        }
    }

    for f in [super::part8_cleanup::generate_cs] {
        let cs = f(&hints, &mut ldm).unwrap();
        let program = Compiler::compile(cs).unwrap();

        scripts.push(program.script);

        let mut witness = vec![];
        for entry in program.hint.iter() {
            match &entry {
                Element::Num(v) => {
                    witness.push(num_to_str(*v));
                }
                Element::Str(v) => {
                    witness.push(v.clone());
                }
            }
        }

        witnesses.push(witness);

        outputs.push(
            convert_to_witness(script! {
                { ldm.hash_var.as_ref().unwrap().value.clone() }
            })
            .unwrap(),
        );
    }

    assert_eq!(scripts.len(), witnesses.len());
    assert_eq!(scripts.len(), outputs.len());

    PlonkAllInformation {
        scripts,
        witnesses,
        outputs,
    }
}

impl CovenantProgram for PlonkVerifierProgram {
    type State = PlonkVerifierState;
    type Input = PlonkVerifierInput;
    const CACHE_NAME: &'static str = "PLONK";

    fn new() -> Self::State {
        PlonkVerifierState {
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
        let all_information = PLONK_ALL_INFORMATION.get_or_init(compute_all_information);

        let mut map = BTreeMap::new();

        for script_idx in 0..(8 + 8 * 8) {
            map.insert(
                script_idx,
                script! {
                    // input:
                    // - old pc
                    // - old stack hash
                    // - new pc
                    // - new stack hash

                    OP_SWAP { script_idx + 1 } OP_EQUALVERIFY
                    OP_ROT { script_idx } OP_EQUALVERIFY

                    if script_idx == 0 {
                        OP_SWAP { vec![0u8; 32] } OP_EQUALVERIFY

                        // stack:
                        // - new stack hash
                        OP_TOALTSTACK
                    } else {
                        // stack:
                        // - old stack hash
                        // - new stack hash
                        OP_TOALTSTACK OP_TOALTSTACK

                        { StackHash::hash_from_hint(1) }
                        OP_FROMALTSTACK OP_EQUALVERIFY
                    }

                    { all_information.scripts[script_idx].clone() }

                    OP_DEPTH
                    { 1 }
                    OP_EQUALVERIFY

                    { StackHash::hash_drop(1) }
                    OP_FROMALTSTACK OP_EQUALVERIFY
                    OP_TRUE
                },
            );
        }

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

    fn run(id: usize, _: &Self::State, _: &Self::Input) -> Result<Self::State> {
        let all_information = PLONK_ALL_INFORMATION.get_or_init(compute_all_information);

        let final_stack = all_information.outputs[id].to_vec();
        let stack_hash = StackHash::compute(&final_stack);
        Ok(Self::State {
            pc: id + 1,
            stack_hash,
            stack: final_stack,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::dsl::plonk::covenant::{
        compute_all_information, PlonkVerifierProgram, PlonkVerifierState, PLONK_ALL_INFORMATION,
    };
    use covenants_gadgets::test::{simulation_test, SimulationInstruction};

    #[test]
    fn test_integration() {
        // The integration assumes a fee rate of 7 sat/vByte.
        // Note that in many situations, the fee rate is only 2 sat/vByte.

        let mut fees = vec![114555, 210434, 103439, 101759, 93233, 81704, 92834];

        for _ in 0..8 {
            fees.extend_from_slice(&[100926, 97300, 97167, 86891, 77679, 86863, 88865, 40467]);
        }

        fees.push(49777);

        println!(
            "total fee assuming 7 sat/vByte: {}",
            fees.iter().sum::<usize>()
        );

        let mut test_generator = |old_state: &PlonkVerifierState| {
            let all_information = PLONK_ALL_INFORMATION.get_or_init(compute_all_information);

            if old_state.pc < fees.len() {
                Some(SimulationInstruction {
                    program_index: old_state.pc,
                    fee: fees[old_state.pc],
                    program_input: all_information.get_input(old_state.pc),
                })
            } else {
                unimplemented!()
            }
        };

        simulation_test::<PlonkVerifierProgram>(72, &mut test_generator);
    }
}
