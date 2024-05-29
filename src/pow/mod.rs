mod bitcoin_script;
pub use bitcoin_script::*;

use sha2::{Digest, Sha256};

/// Check that the prefix leading zeros is greater than `bound_bits`.
pub fn check_leading_zeros(bytes: &[u8], bound_bits: u32) -> bool {
    let mut n_bits = 0;
    // bytes are in little endian order.
    for byte in bytes.iter() {
        if *byte == 0 {
            n_bits += 8;
        } else {
            n_bits += byte.leading_zeros();
            break;
        }
    }
    n_bits >= bound_bits
}

/// Compute the hash from a seed and a nonce.
pub fn hash_with_nonce(seed: &[u8], nonce: u64) -> Vec<u8> {
    let mut concat = seed.to_owned();
    concat.extend(nonce.to_le_bytes().to_vec());

    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, concat);

    hasher.finalize().as_slice().to_vec()
}

/// A handy function for grinding, which finds a nonce that makes the resulting hash with enough zeroes.
pub fn grind_find_nonce(channel_digest: Vec<u8>, n_bits: u32) -> u64 {
    let mut nonce = 0u64;

    loop {
        let hash = hash_with_nonce(&channel_digest, nonce);
        if check_leading_zeros(hash.as_ref(), n_bits) {
            return nonce;
        }
        nonce += 1;
    }
}
