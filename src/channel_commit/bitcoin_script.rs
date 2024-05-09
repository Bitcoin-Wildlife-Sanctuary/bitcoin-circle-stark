use crate::channel_commit::Commitment;
use bitcoin::script::PushBytesBuf;
use bitvm::treepp::pushable::{Builder, Pushable};
use bitvm::treepp::*;

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
            OP_SHA256 OP_CAT OP_SHA256
        }
    }

    pub fn commit_qm31() -> Script {
        script! {
            OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256
        }
    }
}

#[cfg(test)]
mod test {
    use crate::channel_commit::{Commitment, CommitmentGadget};
    use crate::math::{CM31, M31, QM31};
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
