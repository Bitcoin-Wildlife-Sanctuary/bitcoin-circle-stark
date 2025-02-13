use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
use bitcoin::{Address, Network, ScriptBuf, WScriptHash};
use bitcoin_circle_stark::dsl::plonk::covenant::PlonkVerifierProgram;
use covenants_gadgets::{get_script_pub_key, CovenantProgram};

// Function to generate program address
fn get_program_address(network: Network) -> Address {
    let script_pub_key = get_script_pub_key::<PlonkVerifierProgram>();
    Address::from_script(script_pub_key.as_script(), network).unwrap()
}

// Function to generate caboose address
fn get_caboose_address(network: Network) -> Address {
    let init_state = PlonkVerifierProgram::new();
    let hash = PlonkVerifierProgram::get_hash(&init_state);

    let mut bytes = vec![OP_RETURN.to_u8(), OP_PUSHBYTES_36.to_u8()];
    bytes.extend_from_slice(&hash);
    bytes.extend_from_slice(&12u32.to_le_bytes());

    Address::from_script(
        ScriptBuf::new_p2wsh(&WScriptHash::hash(&bytes)).as_script(),
        network,
    )
    .unwrap()
}

fn main() {
    let network = Network::Signet;

    let program_address = get_program_address(network);
    let caboose_address = get_caboose_address(network);

    println!("Program Address: {}", program_address);
    println!("Caboose Address: {}", caboose_address);
}
