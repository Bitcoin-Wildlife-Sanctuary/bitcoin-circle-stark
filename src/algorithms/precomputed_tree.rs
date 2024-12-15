use crate::dsl::primitives::m31::M31Var;
use crate::precomputed_merkle_tree::{PrecomputedMerkleTree, PrecomputedMerkleTreeProof};
use crate::treepp::*;
use crate::utils::{hash, limb_to_be_bits_toaltstack_except_lowest_1bit};
use anyhow::{Error, Result};
use bitcoin_script_dsl::builtins::hash::HashVar;
use bitcoin_script_dsl::bvar::{AllocVar, BVar};
use bitcoin_script_dsl::options::Options;
use bitcoin_script_dsl::stack::Stack;

pub struct PrecomputedVar {
    pub circle_point_x_var: M31Var,
    pub circle_point_y_var: M31Var,
    pub twiddles_var: Vec<M31Var>,
}

pub fn query_and_verify_precomputed_merkle_tree(
    root_hash: &[u8],
    pos: &M31Var,
    proof: &PrecomputedMerkleTreeProof,
) -> Result<PrecomputedVar> {
    let cs = pos.cs();

    let circle_point_x_var = M31Var::new_hint(&cs, proof.circle_point.x)?;
    let circle_point_y_var = M31Var::new_hint(&cs, proof.circle_point.y)?;

    let mut twiddles_var = vec![];
    for &elem in proof.twiddles_elements.iter() {
        twiddles_var.push(M31Var::new_hint(&cs, elem)?);
    }

    let mut siblings_var = vec![];
    for elem in proof.siblings.iter() {
        siblings_var.push(HashVar::new_hint(&cs, elem.to_vec())?);
    }

    let proof_is_valid = PrecomputedMerkleTree::verify(
        TryInto::<[u8; 32]>::try_into(root_hash).unwrap(),
        proof.siblings.len(),
        proof,
        pos.value.0 as usize,
    );
    if !proof_is_valid {
        return Err(Error::msg("Merkle tree proof is invalid"));
    }

    let leaf_hash = HashVar::from(
        [
            circle_point_x_var.clone(),
            circle_point_y_var.clone(),
            twiddles_var.last().unwrap().clone(),
        ]
        .as_slice(),
    );

    let mut variables = vec![];
    variables.push(siblings_var.last().unwrap().variable);
    for (sibling, twiddle) in siblings_var.iter().rev().skip(1).zip(twiddles_var.iter()) {
        variables.push(sibling.variable);
        variables.push(twiddle.variable);
    }
    variables.push(leaf_hash.variable);
    variables.push(pos.variable);

    cs.insert_script_complex(
        query_and_verify_precomputed_merkle_tree_gadget,
        variables,
        &Options::new()
            .with_binary("root_hash", root_hash.to_vec())
            .with_u32("num_layer", siblings_var.len() as u32),
    )?;

    Ok(PrecomputedVar {
        circle_point_x_var,
        circle_point_y_var,
        twiddles_var,
    })
}

fn query_and_verify_precomputed_merkle_tree_gadget(
    _: &mut Stack,
    options: &Options,
) -> Result<Script> {
    let num_layer = options.get_u32("num_layer")?;
    let root_hash = options.get_binary("root_hash")?;

    Ok(script! {
        // stack:
        // - sibling (top)
        // ...
        // - sibling
        // - twiddle
        // ...
        // - leaf_hash
        // - pos

        // convert pos into bits and drop the LSB
        { limb_to_be_bits_toaltstack_except_lowest_1bit(num_layer + 1) }

        for _ in 0..num_layer - 1 {
            // pull the twiddle
            OP_SWAP
            // pull the sibling
            OP_ROT

            // stack:
            // leaf_hash, twiddle, sibling

            // pull a bit
            OP_FROMALTSTACK
            // check if we need to swap, and swap if needed
            OP_IF OP_SWAP OP_ROT OP_ENDIF

            OP_CAT OP_CAT
            hash
        }

        // stack:
        // - sibling (top)
        // - intermediate_hash

        OP_FROMALTSTACK
        // check if we need to swap, and swap if needed
        OP_NOTIF OP_SWAP OP_ENDIF
        OP_CAT
        hash

        { root_hash.to_vec() }
        OP_EQUALVERIFY
    })
}
