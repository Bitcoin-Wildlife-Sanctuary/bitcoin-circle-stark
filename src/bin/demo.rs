use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Txid, WScriptHash};
use bitcoin_circle_stark::fibonacci::fiat_shamir::compute_fiat_shamir_hints;
use bitcoin_circle_stark::fibonacci::fold::compute_fold_hints;
use bitcoin_circle_stark::fibonacci::prepare::compute_prepare_hints;
use bitcoin_circle_stark::fibonacci::quotients::compute_quotients_hints;
use bitcoin_circle_stark::fibonacci::split::{
    FibonacciSplitInput, FibonacciSplitProgram, FibonacciSplitState,
};
use bitcoin_circle_stark::fibonacci::FIB_LOG_SIZE;
use clap::Parser;
use colored::Colorize;
use covenants_gadgets::test::SimulationInstruction;
use covenants_gadgets::{get_script_pub_key, get_tx, CovenantInput, CovenantProgram, DUST_AMOUNT};
use std::io::Write;
use stwo_prover::core::channel::{BWSSha256Channel, Channel};
use stwo_prover::core::fields::m31::{BaseField, M31};
use stwo_prover::core::fields::IntoSlice;
use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hasher;
use stwo_prover::core::vcs::hasher::Hasher;
use stwo_prover::examples::fibonacci::Fibonacci;
use stwo_prover::trace_generation::commit_and_prove;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Funding Txid
    #[arg(short, long)]
    funding_txid: Option<String>,

    /// Txid
    #[arg(short, long)]
    initial_program_txid: Option<String>,
}

fn main() {
    let args = Args::parse();

    let amount = (2800u64 + 473977 + 325136 + 591311 * 8 + 10000) / 7 + 330 * 10;
    let rest = amount - 330 - 400;

    if args.funding_txid.is_none() || args.initial_program_txid.is_none() {
        let script_pub_key = get_script_pub_key::<FibonacciSplitProgram>();

        let program_address =
            Address::from_script(script_pub_key.as_script(), Network::Signet).unwrap();

        let init_state = FibonacciSplitProgram::new();
        let hash = FibonacciSplitProgram::get_hash(&init_state);

        let mut bytes = vec![OP_RETURN.to_u8(), OP_PUSHBYTES_36.to_u8()];
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(&12u32.to_le_bytes());

        let caboose_address = Address::from_script(
            ScriptBuf::new_p2wsh(&WScriptHash::hash(&bytes)).as_script(),
            Network::Signet,
        )
        .unwrap();

        let amount_display =
            (((amount as f64) / 1000.0 / 1000.0 / 100.0) * 10000.0).ceil() / 10000.0;
        let rest_display = (rest as f64) / 1000.0 / 1000.0 / 100.0;

        println!("================= INSTRUCTIONS =================");
        println!("To start with, prepare {} BTC into a UTXO transaction which would be used to fund the transaction fee for the entire demo.",
                 amount_display
        );
        println!(
            "> ./bitcoin-cli --datadir=signet sendtoaddress {} {}",
            "\"[an address in the local wallet]\""
                .on_bright_green()
                .black(),
            amount_display
        );
        println!();
        println!("According to that transaction, send BTC from that UTXO to the program and the state caboose with the initial state");
        println!("> ./bitcoin-cli --datadir=signet createrawtransaction \"[{{\\\"txid\\\":\\\"{}\\\", \\\"vout\\\": {}}}]\" \"[{{\\\"{}\\\":{:.8}}}, {{\\\"{}\\\":0.0000033}}]\"",
            "[txid]".on_bright_green().black(),
            "[vout]".on_bright_green().black(), program_address, rest_display,
            caboose_address
        );
        println!();
        println!("Then, sign the transaction");
        println!(
            "> ./bitcoin-cli --datadir=signet signrawtransactionwithwallet {}",
            "[tx hex]".on_bright_green().black()
        );
        println!();
        println!("Send the signed transaction");
        println!(
            "> ./bitcoin-cli --datadir=signet sendrawtransaction {}",
            "[signed tx hex]".on_bright_green().black()
        );
        println!();
        println!("Call this tool again with the funding txid and initial program id");
        println!("> cargo run -f ");
        println!("================================================");
    } else {
        let fib = Fibonacci::new(FIB_LOG_SIZE, M31::reduce(443693538));

        let trace = fib.get_trace();
        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        let proof = commit_and_prove(&fib.air, channel, vec![trace]).unwrap();

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

        let mut initial_program_txid = [0u8; 32];
        initial_program_txid
            .copy_from_slice(&hex::decode(args.initial_program_txid.unwrap()).unwrap());
        initial_program_txid.reverse();

        let mut funding_txid = [0u8; 32];
        funding_txid.copy_from_slice(&hex::decode(args.funding_txid.unwrap()).unwrap());
        funding_txid.reverse();

        let mut old_state = FibonacciSplitProgram::new();
        let mut old_randomizer = 12u32;
        let mut old_balance = rest;
        let mut old_txid =
            Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&initial_program_txid));

        let mut old_tx_outpoint1 = OutPoint {
            txid: Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&funding_txid)),
            vout: 0,
        };

        let get_instruction = |old_state: &FibonacciSplitState| {
            if old_state.pc == 0 {
                Some(SimulationInstruction::<FibonacciSplitProgram> {
                    program_index: 0,
                    fee: 67711,
                    program_input: FibonacciSplitInput::FiatShamir(Box::new(
                        fiat_shamir_hints.clone(),
                    )),
                })
            } else if old_state.pc == 1 {
                Some(SimulationInstruction::<FibonacciSplitProgram> {
                    program_index: 1,
                    fee: 46448,
                    program_input: FibonacciSplitInput::Prepare(
                        old_state.stack.clone(),
                        prepare_hints.clone(),
                    ),
                })
            } else if old_state.pc >= 2 && old_state.pc <= 9 {
                let i = old_state.pc - 2;
                Some(SimulationInstruction {
                    program_index: old_state.pc,
                    fee: 84473,
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

        let mut txs = Vec::new();

        for _ in 0..10 {
            let next = get_instruction(&old_state).unwrap();

            let mut new_balance = old_balance;
            new_balance -= next.fee as u64; // as for transaction fee
            new_balance -= DUST_AMOUNT;

            let info = CovenantInput {
                old_randomizer,
                old_balance,
                old_txid,
                input_outpoint1: old_tx_outpoint1,
                input_outpoint2: None,
                optional_deposit_input: None,
                new_balance,
            };

            let new_state =
                FibonacciSplitProgram::run(next.program_index, &old_state, &next.program_input)
                    .unwrap();

            let (tx_template, randomizer) = get_tx::<FibonacciSplitProgram>(
                &info,
                next.program_index,
                &old_state,
                &new_state,
                &next.program_input,
            );

            txs.push(tx_template.tx.clone());

            old_state = new_state;
            old_randomizer = randomizer;
            old_balance = new_balance;
            old_txid = tx_template.tx.compute_txid();

            old_tx_outpoint1 = tx_template.tx.input[0].previous_output;
        }

        for (i, tx) in txs.iter().enumerate() {
            let mut bytes = vec![];
            tx.consensus_encode(&mut bytes).unwrap();

            let mut fs = std::fs::File::create(format!("./tx-{}.txt", i + 1)).unwrap();
            fs.write_all(hex::encode(bytes).as_bytes()).unwrap();
        }

        println!("================= INSTRUCTIONS =================");
        println!("All 10 transactions have been generated and stored in the current directory.");
    }
}
