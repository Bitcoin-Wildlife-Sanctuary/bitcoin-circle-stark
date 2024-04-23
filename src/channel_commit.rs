use crate::fields::{CM31, M31, QM31};
use bitcoin::script::PushBytesBuf;
use bitvm::treepp::pushable::{Builder, Pushable};
use bitvm::treepp::*;
use sha2::{Digest, Sha256};

// every commitment is a 32-bytes SHA256 hash
#[derive(Clone, Default, Debug)]
pub struct Commitment(pub [u8; 32]);

impl Commitment {
    pub fn commit_m31(v: M31) -> Self {
        let mut bytes = Vec::new();
        let mut res = Self::default();

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

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &bytes);

        res.0.copy_from_slice(hasher.finalize().as_slice());

        res
    }

    pub fn commit_cm31(v: CM31) -> Self {
        let mut res = Self::default();

        let c0 = Self::commit_m31(v.0);
        let c1 = Self::commit_m31(v.1);
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &c0.0);
        Digest::update(&mut hasher, &c1.0);

        res.0.copy_from_slice(hasher.finalize().as_slice());

        res
    }

    pub fn commit_qm31(v: QM31) -> Self {
        let mut res = Self::default();

        let c0 = Self::commit_cm31(v.0);
        let c1 = Self::commit_cm31(v.1);
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &c0.0);
        Digest::update(&mut hasher, &c1.0);

        res.0.copy_from_slice(hasher.finalize().as_slice());

        res
    }
}

impl Pushable for M31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        self.0.bitcoin_script_push(builder)
    }
}

impl Pushable for CM31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let builder = self.0.bitcoin_script_push(builder);
        self.1.bitcoin_script_push(builder)
    }
}

impl Pushable for QM31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let builder = self.0.bitcoin_script_push(builder);
        self.1.bitcoin_script_push(builder)
    }
}

impl Pushable for Commitment {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let mut buf = PushBytesBuf::new();
        buf.extend_from_slice(&self.0).unwrap();
        builder.push_slice(buf)
    }
}

pub struct CommitmentGadget;
impl CommitmentGadget {
    pub fn commit_m31() -> Script {
        script! {
            OP_SHA256
        }
    }

    pub fn commit_cm31() -> Script {
        script! {
            OP_SWAP OP_SHA256
            OP_SWAP OP_SHA256
            OP_CAT OP_SHA256
        }
    }

    pub fn commit_qm31() -> Script {
        script! {
            { Self::commit_cm31() } OP_TOALTSTACK
            { Self::commit_cm31() } OP_FROMALTSTACK
            OP_CAT OP_SHA256
        }
    }
}

#[cfg(test)]
mod test {
    use crate::channel_commit::{Commitment, CommitmentGadget};
    use crate::fields::{CM31, M31, QM31};
    use bitcoin_script::script;
    use bitvm::treepp::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_commit_m31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let commit_script = CommitmentGadget::commit_m31();
        println!("M31.commit() = {} bytes", commit_script.len());

        for _ in 0..100 {
            let a = M31::reduce(prng.next_u64());
            let b = Commitment::commit_m31(a);

            let script = script! {
                { a.clone() }
                { commit_script.clone() }
                { b.clone() }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_commit_cm31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let commit_script = CommitmentGadget::commit_cm31();
        println!("CM31.commit() = {} bytes", commit_script.len());

        for _ in 0..100 {
            let a = CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64()));
            let b = Commitment::commit_cm31(a);

            let script = script! {
                { a.clone() }
                { commit_script.clone() }
                { b.clone() }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_commit_qm31() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let commit_script = CommitmentGadget::commit_qm31();
        println!("QM31.commit() = {} bytes", commit_script.len());

        for _ in 0..100 {
            let a = QM31(
                CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
                CM31(M31::reduce(prng.next_u64()), M31::reduce(prng.next_u64())),
            );
            let b = Commitment::commit_qm31(a);

            let script = script! {
                { a.clone() }
                { commit_script.clone() }
                { b.clone() }
                OP_EQUAL
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }

        // make sure OP_CAT is not OP_SUCCESS
        let script = script! {
            OP_CAT
            OP_RETURN
        };
        let exec_result = execute_script(script);
        assert!(!exec_result.success);
    }
}
