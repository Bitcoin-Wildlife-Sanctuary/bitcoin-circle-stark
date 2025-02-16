use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Txid, WScriptHash};
use bitcoin_circle_stark::dsl::plonk::covenant::{
    compute_all_information, PlonkVerifierProgram, PlonkVerifierState, PLONK_ALL_INFORMATION,
};
use clap::Parser;
use colored::Colorize;
use covenants_gadgets::test::SimulationInstruction;
use covenants_gadgets::{get_script_pub_key, get_tx, CovenantInput, CovenantProgram, DUST_AMOUNT};
use std::io::Write;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Funding Txid
    #[arg(short, long)]
    funding_txid: Option<String>,

    /// Txid
    #[arg(short, long)]
    initial_program_txid: Option<String>,

    #[arg(short, long, default_value = "42")]
    randomizer: u32,
}

const OUTPUT_DIR: &str = "./demo";
const FEE_RATE: u64 = 1500; // 1 for signet, ~1500 for fractal
const NETWORK: Network = Network::Bitcoin;

fn print_state_info(state: &PlonkVerifierState, step: usize) {
    println!("\n{}", "=".repeat(50));
    println!("Step {}: Current State", step);
    println!("{}", "-".repeat(30));
    println!("Program Counter (pc): {}", state.pc);
    // display stack hash as hex
    println!("Stack Hash: {}", hex::encode(&state.stack_hash));
    println!("Stack Length: {}", state.stack.len());
}

fn print_covenant_input(input: &CovenantInput, _step: usize) {
    println!("\n{}", "Step: Covenant Input".blue());
    println!("{}", "-".repeat(30));
    println!("Old Randomizer: {}", input.old_randomizer);
    println!("Old Balance: {} sats", input.old_balance);
    println!("Old TxId: {}", input.old_txid);
    println!(
        "Input Outpoint1: {}:{}",
        input.input_outpoint1.txid, input.input_outpoint1.vout
    );
    println!("New Balance: {} sats", input.new_balance);
    println!(
        "Balance Change: -{} sats",
        input.old_balance - input.new_balance
    );
}

fn print_transaction_info(tx: &bitcoin::Transaction, _step: usize) {
    println!("\n{}", "Step: Generated Transaction".green());
    println!("{}", "-".repeat(30));
    println!("TxId: {}", tx.compute_txid());
    println!("Input Count: {}", tx.input.len());
    println!("Output Count: {}", tx.output.len());
    println!("Outputs:");
    for (i, output) in tx.output.iter().enumerate() {
        println!("  Output {}: {} sats", i, output.value);
    }
}

fn main() {
    let args = Args::parse();

    let mut fees = vec![114555, 210434, 103439, 101759, 93233, 81704, 92834];

    for _ in 0..8 {
        fees.extend_from_slice(&[100926, 97300, 97167, 86891, 77679, 86863, 88865, 40467]);
    }

    fees.push(49777);

    let amount =
        (fees.iter().sum::<usize>() as u64 + 10000) / 7 * FEE_RATE + 330 * 74 + 400 * FEE_RATE;
    let amount_display = (((amount as f64) / 1000.0 / 1000.0 / 100.0) * 10000.0).ceil() / 10000.0;
    let actual_amount = (amount_display * 100.0 * 1000.0 * 1000.0) as u64;
    let rest = actual_amount - 330 - 400 * FEE_RATE;

    if args.funding_txid.is_none() || args.initial_program_txid.is_none() {
        let script_pub_key = get_script_pub_key::<PlonkVerifierProgram>();

        let program_address = Address::from_script(script_pub_key.as_script(), NETWORK).unwrap();

        let init_state = PlonkVerifierProgram::new();
        let hash = PlonkVerifierProgram::get_hash(&init_state);

        let mut bytes = vec![OP_RETURN.to_u8(), OP_PUSHBYTES_36.to_u8()];
        bytes.extend_from_slice(&hash);
        bytes.extend_from_slice(&args.randomizer.to_le_bytes());

        let caboose_address = Address::from_script(
            ScriptBuf::new_p2wsh(&WScriptHash::hash(&bytes)).as_script(),
            NETWORK,
        )
        .unwrap();

        let rest_display = (rest as f64) / 1000.0 / 1000.0 / 100.0;

        println!("================= INSTRUCTIONS =================");
        println!("To start with, prepare {} BTC into a UTXO transaction which would be used to fund the transaction fee for the entire demo-fibonacci.",
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
        println!(
            "> cargo run -- -f {} -i {}",
            "[funding txid]".on_bright_green().black(),
            "[initial program txid]".on_bright_green().black()
        );
        println!("================================================");
    } else {
        let mut initial_program_txid = [0u8; 32];
        initial_program_txid
            .copy_from_slice(&hex::decode(args.initial_program_txid.unwrap()).unwrap());
        initial_program_txid.reverse();

        let mut funding_txid = [0u8; 32];
        funding_txid.copy_from_slice(&hex::decode(args.funding_txid.unwrap()).unwrap());
        funding_txid.reverse();

        let mut old_state = PlonkVerifierProgram::new();
        let mut old_randomizer = args.randomizer;
        let mut old_balance = rest;
        let mut old_txid =
            Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&initial_program_txid));

        let mut old_tx_outpoint1 = OutPoint {
            txid: Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&funding_txid)),
            vout: 0, // change this number if the funding tx is not the first output
        };

        let mut txs = Vec::new();

        let get_instruction = |old_state: &PlonkVerifierState| {
            let all_information = PLONK_ALL_INFORMATION.get_or_init(compute_all_information);

            if old_state.pc < fees.len() {
                Some(SimulationInstruction::<PlonkVerifierProgram> {
                    program_index: old_state.pc,
                    fee: (fees[old_state.pc] as f64 / 7.0 * (FEE_RATE as f64)).ceil() as usize,
                    program_input: all_information.get_input(old_state.pc),
                })
            } else {
                unimplemented!()
            }
        };

        for step in 0..72 {
            let next = get_instruction(&old_state).unwrap();

            println!("\n{}", "=".repeat(80));
            println!(
                "{}",
                format!("Processing Transaction {} of 72", step + 1).yellow()
            );
            println!("{}", "=".repeat(80));

            print_state_info(&old_state, step + 1);

            let mut new_balance = old_balance;
            new_balance -= next.fee as u64;
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

            print_covenant_input(&info, step + 1);

            let new_state =
                PlonkVerifierProgram::run(next.program_index, &old_state, &next.program_input)
                    .unwrap();

            println!("\nState Transition:");
            println!("Old PC: {} -> New PC: {}", old_state.pc, new_state.pc);
            println!(
                "Old Stack Size: {} -> New Stack Size: {}",
                old_state.stack.len(),
                new_state.stack.len()
            );

            let (tx_template, randomizer) = get_tx::<PlonkVerifierProgram>(
                &info,
                next.program_index,
                &old_state,
                &new_state,
                &next.program_input,
            );

            print_transaction_info(&tx_template.tx, step + 1);

            txs.push(tx_template.tx.clone());

            old_state = new_state;
            old_randomizer = randomizer;
            old_balance = new_balance;
            old_txid = tx_template.tx.compute_txid();

            old_tx_outpoint1 = tx_template.tx.input[0].previous_output;
        }

        // Create directory if it doesn't exist
        std::fs::create_dir_all(OUTPUT_DIR).unwrap();

        for (i, tx) in txs.iter().enumerate() {
            let mut bytes = vec![];
            tx.consensus_encode(&mut bytes).unwrap();

            // Write the transaction to a file
            let mut fs = std::fs::File::create(format!("{}/tx-{}.txt", OUTPUT_DIR, i + 1)).unwrap();
            fs.write_all(hex::encode(bytes).as_bytes()).unwrap();
        }

        println!("================= INSTRUCTIONS =================");
        println!("All 72 transactions have been generated and stored in the current directory.");
    }
}
