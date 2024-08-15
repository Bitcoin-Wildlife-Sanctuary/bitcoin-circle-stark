use crate::utils::trim_m31;
use bitcoin::script::PushBytesBuf;
use sha2::{Digest, Sha256};
use std::ops::Neg;
use stwo_prover::core::channel::Channel;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::QM31;

mod bitcoin_script;
use crate::treepp::pushable::{Builder, Pushable};
pub use bitcoin_script::*;

pub use stwo_prover::core::channel::Sha256Channel;
use stwo_prover::core::vcs::sha256_hash::Sha256Hash;

/// A wrapper trait to implement hint-related method for channels.
pub trait ChannelWithHint: Channel {
    /// Draw raw m31 elements.
    fn draw_m31_and_hints(&mut self, m: usize) -> (Vec<M31>, DrawHints);

    /// Draw one qm31 and compute the hints.
    fn draw_felt_and_hints(&mut self) -> (QM31, DrawHints) {
        let res = self.draw_m31_and_hints(4);
        (
            QM31::from_m31(res.0[0], res.0[1], res.0[2], res.0[3]),
            res.1,
        )
    }

    /// Draw five queries and compute the hints.
    fn draw_queries_and_hints(&mut self, m: usize, logn: usize) -> (Vec<usize>, DrawHints) {
        let res = self.draw_m31_and_hints(m);

        let mut trimmed_results = vec![0usize; m];
        for (trimmed_result, result) in trimmed_results.iter_mut().zip(res.0.iter()) {
            *trimmed_result = trim_m31(result.0, logn) as usize;
        }

        (trimmed_results, res.1)
    }
}

impl ChannelWithHint for Sha256Channel {
    fn draw_m31_and_hints(&mut self, m: usize) -> (Vec<M31>, DrawHints) {
        let mut extract = vec![];
        let mut count = 0;

        while count < m {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, self.digest);
            Digest::update(&mut hasher, [0u8]);
            extract.extend_from_slice(hasher.finalize().as_slice());

            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, self.digest);
            self.digest = Sha256Hash::from(hasher.finalize().to_vec());

            count += 8;
        }

        generate_hints(m, &extract)
    }
}

fn generate_hints(m: usize, extract: &[u8]) -> (Vec<M31>, DrawHints) {
    let mut res_m31 = vec![M31::default(); m];
    let mut res_hints = DrawHints::default();

    for i in 0..m {
        let res = u32::from_le_bytes(<[u8; 4]>::try_from(&extract[i * 4..(i + 1) * 4]).unwrap())
            & 0x7fffffff;

        res_hints.0.push(if extract[(i + 1) * 4 - 1] & 0x80 != 0 {
            if res == 0 {
                BitcoinIntegerEncodedData::NegativeZero
            } else {
                BitcoinIntegerEncodedData::Other((res as i64).neg())
            }
        } else {
            BitcoinIntegerEncodedData::Other(res as i64)
        });

        res_m31[i] = M31::from(res);
    }

    if m % 8 != 0 {
        res_hints.1 = extract[m * 4..].to_vec();
    }

    (res_m31, res_hints)
}

/// Basic hint structure for extracting a single qm31 element.
#[derive(Clone, Copy)]
pub enum BitcoinIntegerEncodedData {
    /// negative zero (will be represented by 0x80).
    NegativeZero,
    /// any Bitcoin integer other than the negative zero.
    Other(i64),
}

impl Default for BitcoinIntegerEncodedData {
    fn default() -> Self {
        Self::Other(0)
    }
}

impl Pushable for BitcoinIntegerEncodedData {
    fn bitcoin_script_push(&self, builder: Builder) -> Builder {
        match self {
            BitcoinIntegerEncodedData::NegativeZero => {
                builder.push_slice(PushBytesBuf::from([0x80]))
            }
            BitcoinIntegerEncodedData::Other(v) => builder.push_int(*v),
        }
    }
}

#[derive(Clone, Default)]
/// Hints for drawing m31 elements.
pub struct DrawHints(pub Vec<BitcoinIntegerEncodedData>, pub Vec<u8>);

impl Pushable for DrawHints {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        let n = self.0.len();

        if n % 8 == 0 {
            assert!(self.1.is_empty());
        } else {
            assert_eq!(self.1.len(), 32 - (n % 8) * 4);
        }

        for i in 0..n {
            builder = self.0[i].bitcoin_script_push(builder);
        }

        if n % 8 != 0 {
            builder = self.1.clone().bitcoin_script_push(builder);
        }

        builder
    }
}
