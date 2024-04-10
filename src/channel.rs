use crate::cfri::fields::{M31, QM31};
use crate::channel_commit::{Commitment, CommitmentGadget};
use crate::channel_extract::{Extraction5M31, ExtractionQM31, Extractor, ExtractorGadget};
use crate::utils::{trim_m31, trim_m31_gadget};
use bitvm::treepp::*;
use sha2::{Digest, Sha256};

pub struct Channel {
    state: [u8; 32],
}

impl Channel {
    pub fn new(hash: [u8; 32]) -> Self {
        Self { state: hash }
    }
    pub fn mix_with_commitment(&mut self, commitment: &Commitment) {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &self.state);
        Digest::update(&mut hasher, commitment.0);
        self.state.copy_from_slice(hasher.finalize().as_slice());
    }

    pub fn mix_with_el(&mut self, el: &QM31) {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &self.state);
        Digest::update(&mut hasher, Commitment::commit_qm31(el.clone()).0);
        self.state.copy_from_slice(hasher.finalize().as_slice());
    }

    pub fn draw_element(&mut self) -> (QM31, ExtractionQM31) {
        let mut extract = [0u8; 32];

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &self.state);
        Digest::update(&mut hasher, "0");
        extract.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &self.state);
        self.state.copy_from_slice(hasher.finalize().as_slice());

        Extractor::extract_qm31(&extract)
    }

    pub fn draw_5queries(&mut self, logn: usize) -> ([M31; 5], Extraction5M31) {
        let mut extract = [0u8; 32];

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &self.state);
        Digest::update(&mut hasher, "0");
        extract.copy_from_slice(hasher.finalize().as_slice());

        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, &self.state);
        self.state.copy_from_slice(hasher.finalize().as_slice());

        let mut res = Extractor::extract_5m31(&extract);

        for v in res.0.iter_mut() {
            *v.0 = trim_m31(v.0, logn);
        }

        res
    }
}

pub struct ChannelGadget;

impl ChannelGadget {
    pub fn new(hash: [u8; 32]) -> Script {
        script! {
            { hash.to_vec() }
        }
    }

    pub fn mix_with_commitment() -> Script {
        script! {
            OP_CAT OP_SHA256
        }
    }

    pub fn mix_with_el() -> Script {
        script! {
            { CommitmentGadget::commit_qm31() }
            OP_CAT OP_SHA256
        }
    }

    pub fn draw_element_using_hint() -> Script {
        script! {
            OP_DUP OP_SHA256 OP_SWAP
            OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT OP_SHA256
            { ExtractorGadget::unpack_qm31() }
        }
    }

    pub fn draw_5queries_using_hint(logn: usize) -> Script {
        script! {
            OP_DUP OP_SHA256 OP_SWAP
            OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT OP_SHA256
            { ExtractorGadget::unpack_5m31() }
            { trim_m31_gadget(logn) } OP_TOALTSTACK
            { trim_m31_gadget(logn) } OP_TOALTSTACK
            { trim_m31_gadget(logn) } OP_TOALTSTACK
            { trim_m31_gadget(logn) } OP_TOALTSTACK
            { trim_m31_gadget(logn) }
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
        }
    }
}
