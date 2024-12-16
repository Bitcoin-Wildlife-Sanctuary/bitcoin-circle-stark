use crate::dsl::primitives::m31::M31Var;
use crate::merkle_tree::MerkleTreeTwinProof;
use crate::treepp::*;
use crate::utils::{hash, limb_to_be_bits_toaltstack_except_lowest_1bit};
use anyhow::Error;
use anyhow::Result;
use bitcoin_script_dsl::builtins::hash::HashVar;
use bitcoin_script_dsl::bvar::{AllocVar, BVar};
use bitcoin_script_dsl::options::Options;
use bitcoin_script_dsl::stack::Stack;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

pub fn query_and_verify_merkle_twin_tree(
    root_hash_var: &HashVar,
    pos_var: &M31Var,
    proof: &MerkleTreeTwinProof,
) -> Result<(Vec<M31Var>, Vec<M31Var>)> {
    let mut pos = pos_var.value.0;
    if pos % 2 == 1 {
        pos -= 1;
    }

    let proof_is_valid = proof.verify(
        &Sha256Hash::from(root_hash_var.value.as_slice()),
        proof.path.siblings.len() + 1,
        pos as usize,
    );
    if !proof_is_valid {
        return Err(Error::msg("Merkle tree proof is invalid"));
    }

    let cs = root_hash_var.cs().and(&pos_var.cs());

    let mut left_var = vec![];
    for &elem in proof.left.iter() {
        left_var.push(M31Var::new_hint(&cs, elem)?);
    }

    let left_hash = HashVar::from(left_var.as_slice());

    let mut right_var = vec![];
    for &elem in proof.right.iter() {
        right_var.push(M31Var::new_hint(&cs, elem)?);
    }

    let right_hash = HashVar::from(right_var.as_slice());

    let mut path_var = vec![];
    for elem in proof.path.siblings.iter().rev() {
        path_var.push(HashVar::new_hint(&cs, elem.as_ref().to_vec())?);
    }

    let mut variables = root_hash_var.variables();
    for var in path_var.iter() {
        variables.extend(var.variables())
    }
    variables.extend(left_hash.variables());
    variables.extend(right_hash.variables());
    variables.push(pos_var.variable);

    cs.insert_script_complex(
        query_and_verify_merkle_twin_tree_gadget,
        variables,
        &Options::new().with_u32("logn", (proof.path.siblings.len() + 1) as u32),
    )?;

    Ok((left_var, right_var))
}

fn query_and_verify_merkle_twin_tree_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let logn = options.get_u32("logn")?;

    Ok(script! {
        // stack:
        // - root_hash
        // - merkle_path
        // - left_hash
        // - right_hash
        // - pos

        { limb_to_be_bits_toaltstack_except_lowest_1bit(logn) }
        // hash the right_hash again
        hash
        // hash the left_hash again
        OP_SWAP hash

        // combine left_hash and right_hash
        OP_SWAP OP_CAT hash

        // stack:
        // - root_hash
        // - merkle_path
        // - cur_hash

        for _ in 0..(logn - 1) {
            OP_FROMALTSTACK OP_NOTIF OP_SWAP OP_ENDIF
            OP_CAT hash
        }

        OP_EQUALVERIFY
    })
}
