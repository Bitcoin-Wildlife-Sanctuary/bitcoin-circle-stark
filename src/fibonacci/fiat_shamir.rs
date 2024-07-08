use crate::air::CompositionHint;
use crate::channel::DrawHints;
use crate::oods::OODSHint;
use crate::pow::PoWHint;
use crate::treepp::pushable::{Builder, Pushable};
use stwo_prover::core::fields::qm31::{SecureField, QM31};
use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hash;

/// Hints for performing the Fiat-Shamir transform until finalziing the queries.
pub struct FiatShamirHints {
    /// Commitments from the proof.
    pub commitments: [BWSSha256Hash; 2],

    /// random_coeff comes from adding `proof.commitments[0]` to the channel.
    pub random_coeff_hint: DrawHints,

    /// OODS hint.
    pub oods_hint: OODSHint,

    /// trace oods values.
    pub trace_oods_values: [SecureField; 3],

    /// composition odds raw values.
    pub composition_oods_values: [SecureField; 4],

    /// Composition hint.
    pub composition_hint: CompositionHint,

    /// second random_coeff hint
    pub random_coeff_hint2: DrawHints,

    /// circle_poly_alpha hint
    pub circle_poly_alpha_hint: DrawHints,

    /// fri commit and hints for deriving the folding parameter
    pub fri_commitment_and_folding_hints: Vec<(BWSSha256Hash, DrawHints)>,

    /// last layer poly (assuming only one element)
    pub last_layer: QM31,

    /// PoW hint
    pub pow_hint: PoWHint,

    /// Query sampling hints
    pub queries_hints: DrawHints,
}

impl Pushable for &FiatShamirHints {
    fn bitcoin_script_push(self, mut builder: Builder) -> Builder {
        builder = self.commitments[0].bitcoin_script_push(builder);
        builder = (&self.random_coeff_hint).bitcoin_script_push(builder);
        builder = self.commitments[1].bitcoin_script_push(builder);
        builder = (&self.oods_hint).bitcoin_script_push(builder);
        for v in self.trace_oods_values.iter() {
            builder = v.bitcoin_script_push(builder);
        }
        for v in self.composition_oods_values.iter() {
            builder = v.bitcoin_script_push(builder);
        }
        builder = (&self.composition_hint).bitcoin_script_push(builder);
        builder = (&self.random_coeff_hint2).bitcoin_script_push(builder);
        builder = (&self.circle_poly_alpha_hint).bitcoin_script_push(builder);
        for (c, h) in self.fri_commitment_and_folding_hints.iter() {
            builder = c.bitcoin_script_push(builder);
            builder = h.bitcoin_script_push(builder);
        }
        builder = self.last_layer.bitcoin_script_push(builder);
        builder = (&self.pow_hint).bitcoin_script_push(builder);
        builder = (&self.queries_hints).bitcoin_script_push(builder);
        builder
    }
}

impl Pushable for FiatShamirHints {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        (&self).bitcoin_script_push(builder)
    }
}
