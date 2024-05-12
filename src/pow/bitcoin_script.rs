use bitvm::treepp::*;
use rust_bitcoin_u31_or_u30::unroll;
use crate::pow::hash_with_nonce;

pub struct PowGadget;
impl PowGadget {
    //input:
    //CHANNEL
    //NONCE
    //SUFFIX (hint)
    //MSB - most significant byte (hint)
    //
    //panics if 0^(n_bits-n_bits%8)||MSB||SUFFIX != sha256(CHANNEL||NONCE)
    //panics if MSB does not start with n_bits%8 zeroes
    //
    //output:
    //CHANNEL'=sha256(CHANNEL||NONCE)
    pub fn verify_mix_nonce(n_bits: usize) -> Script {
        script! {
            //check MSB here with bit decomposition
            
            

            /* 
            unroll(0, |i| {
                let a = 1 << (30 - i);
                let b = a - 1;
                script! {
                    OP_DUP
                    { b } OP_GREATERTHAN
                    OP_SWAP OP_OVER
                    OP_IF { a } OP_SUB OP_ENDIF
                }
            })
            */

            OP_SWAP
            OP_CAT //MSB||SUFFIX

            OP_ROT
            OP_ROT //stack looks like: MSB||SUFFIX, CHANNEL, NONCE
            OP_CAT //stack looks like: MSB||SUFFIX, CHANNEL||NONCE
            OP_SHA256
            OP_DUP
            OP_TOALTSTACK //put channel'=sha256(CHANNEL||NONCE) in altstack
            OP_SWAP
            { vec![0u8; (n_bits-n_bits%8)/8] }
            OP_SWAP
            OP_CAT
            OP_EQUALVERIFY
            OP_FROMALTSTACK
        }
    }

    //output:
    //NONCE
    //SUFFIX (hint)
    //MSB - most significant byte (hint)
    pub fn hint_hash_with_nonce(channel_digest: Vec<u8>, nonce: u64, n_bits: usize) -> Script {
        
        let digest = hash_with_nonce(&channel_digest, nonce);

        script! {
            { nonce.to_le_bytes().to_vec() }
            { digest[(n_bits-n_bits%8)/8+1..].to_vec() }
            { digest[(n_bits-n_bits%8)/8] as u32 }
            { 0x79u8 }
        }
    }
}

#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use bitvm::treepp::*;

    use crate::pow::{bitcoin_script::PowGadget, grind_find_nonce, hash_with_nonce};

    #[test]
    fn test_hash_with_nonce() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut channel_digest = [0u8; 32].to_vec();

        for i in 0..32 {
            channel_digest[i] = prng.gen();
        } 

        let nonce = prng.gen();

        let res = hash_with_nonce(&channel_digest, nonce);

        let script = script! {
            { PowGadget::hint_hash_with_nonce(channel_digest.clone(), nonce, 0) }
            { res.to_vec() }
            OP_EQUALVERIFY
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    //need to test prove and verify separately with hardcoded stuff

    #[test]
    fn test_pow() {
        let n_bits: usize=12; //23?

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut channel_digest = [0u8; 32].to_vec();

        for i in 0..32 {
            channel_digest[i] = prng.gen();
        }

        let nonce =  grind_find_nonce(channel_digest.clone(), n_bits.try_into().unwrap());

        let script = script! {
            { channel_digest.clone() }
            { PowGadget::hint_hash_with_nonce(channel_digest.clone(), nonce, n_bits) }
            { PowGadget::verify_mix_nonce(n_bits)}
            { channel_digest.clone() }
            { nonce.to_le_bytes().to_vec() }
            OP_CAT
            OP_SHA256
            OP_EQUALVERIFY //checking that indeed channel' = sha256(channel||nonce)
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
