use crate::fields::{CM31, M31, QM31};
use sha2::{Digest, Sha256};

mod bitcoin_script;
pub use bitcoin_script::*;

// every commitment is a 32-bytes SHA256 hash
#[derive(Clone, Default, Debug)]
pub struct Commitment(pub [u8; 32]);

impl Commitment {
    fn num_to_bytes(v: M31) -> Vec<u8> {
        let mut bytes = Vec::new();

        let mut v = v.0;
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }

        if bytes.last().is_some() {
            if bytes.last().unwrap() & 0x80 != 0 {
                bytes.push(0);
            }
        }
        bytes
    }

    pub fn commit_m31(v: M31) -> Self {
        let mut res = Self::default();

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &Self::num_to_bytes(v));

        res.0.copy_from_slice(hasher.finalize().as_slice());

        res
    }

    pub fn commit_cm31(v: CM31) -> Self {
        let mut res = Self::default();

        let c1 = Self::commit_m31(v.1);
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &Self::num_to_bytes(v.0));
        Digest::update(&mut hasher, &c1.0);

        res.0.copy_from_slice(hasher.finalize().as_slice());

        res
    }

    pub fn commit_qm31(v: QM31) -> Self {
        let mut res = Self::default();

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &Self::num_to_bytes(v.1 .0));
        Digest::update(&mut hasher, &Self::commit_m31(v.1 .1).0);
        res.0.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &Self::num_to_bytes(v.0 .1));
        Digest::update(&mut hasher, &res.0);
        res.0.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &Self::num_to_bytes(v.0 .0));
        Digest::update(&mut hasher, &res.0);
        res.0.copy_from_slice(hasher.finalize().as_slice());

        res
    }
}
