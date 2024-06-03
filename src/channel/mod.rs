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

pub use stwo_prover::core::channel::BWSSha256Channel as Sha256Channel;
use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hash;

/// A wrapper trait to implement hint-related method for channels.
pub trait ChannelWithHint: Channel {
    /// Draw raw m31 elements.
    fn draw_m31_and_hints<const N: usize>(&mut self) -> ([M31; N], DrawHints<N>);

    /// Draw one qm31 and compute the hints.
    fn draw_felt_and_hints(&mut self) -> (QM31, DrawHints<4>) {
        let res = self.draw_m31_and_hints::<4>();
        (QM31::from_m31_array(res.0), res.1)
    }

    /// Draw five queries and compute the hints.
    fn draw_5queries(&mut self, logn: usize) -> ([usize; 5], DrawHints<5>) {
        let res = self.draw_m31_and_hints::<5>();

        let mut trimmed_results = [0usize; 5];
        for (trimmed_result, result) in trimmed_results.iter_mut().zip(res.0.iter()) {
            *trimmed_result = trim_m31(result.0, logn) as usize;
        }

        (trimmed_results, res.1)
    }
}

impl ChannelWithHint for Sha256Channel {
    fn draw_m31_and_hints<const N: usize>(&mut self) -> ([M31; N], DrawHints<N>) {
        let mut extract = vec![];
        let mut count = 0;

        while count < N {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, self.digest);
            Digest::update(&mut hasher, [0u8]);
            extract.extend_from_slice(hasher.finalize().as_slice());

            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, self.digest);
            self.digest = BWSSha256Hash::from(hasher.finalize().to_vec());

            count += 8;
        }

        generate_hints(&extract)
    }
}

fn generate_hints<const N: usize>(extract: &[u8]) -> ([M31; N], DrawHints<N>) {
    let mut res_m31 = [M31::default(); N];
    let mut res_hints = DrawHints::<N>::default();

    for i in 0..N {
        let res = u32::from_le_bytes(<[u8; 4]>::try_from(&extract[i * 4..(i + 1) * 4]).unwrap())
            & 0x7fffffff;

        res_hints.0[i] = if extract[(i + 1) * 4 - 1] & 0x80 != 0 {
            if res == 0 {
                BitcoinIntegerEncodedData::NegativeZero
            } else {
                BitcoinIntegerEncodedData::Other((res as i64).neg())
            }
        } else {
            BitcoinIntegerEncodedData::Other(res as i64)
        };

        res_m31[i] = M31::from(res.saturating_sub(1));
    }

    if N % 8 != 0 {
        res_hints.1 = extract[N * 4..].to_vec();
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
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        match self {
            BitcoinIntegerEncodedData::NegativeZero => {
                builder.push_slice(PushBytesBuf::from([0x80]))
            }
            BitcoinIntegerEncodedData::Other(v) => builder.push_int(v),
        }
    }
}

#[derive(Clone)]
/// Hints for drawing m31 elements.
pub struct DrawHints<const N: usize>(pub [BitcoinIntegerEncodedData; N], pub Vec<u8>);

impl<const N: usize> Default for DrawHints<N> {
    fn default() -> Self {
        Self([BitcoinIntegerEncodedData::default(); N], vec![])
    }
}

/// Hints for drawing a QM31 element (most common).
pub type DrawQM31Hints = DrawHints<4>;
