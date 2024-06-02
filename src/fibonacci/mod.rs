mod bitcoin_script;
pub use bitcoin_script::*;
use num_traits::One;
use stwo_prover::core::{
    circle::{CirclePoint, Coset},
    constraints::{coset_vanishing, pair_vanishing},
    fields::{
        m31::{BaseField, M31},
        ExtensionOf, FieldExpOps,
    },
};

///Fibonacci composition polynomial-related methods are PRIVATE, so we need to copy-paste them from stwo!
/// TODO: solve this problem
pub struct FibonacciComposition;

impl FibonacciComposition {
    ///step
    fn step_constraint_eval_quotient_by_mask<F: ExtensionOf<BaseField>>(
        log_size: u32,
        point: CirclePoint<F>,
        mask: &[F; 3],
    ) -> F {
        let constraint_zero_domain = Coset::subgroup(log_size);
        let constraint_value = mask[0].square() + mask[1].square() - mask[2];
        let selector = pair_vanishing(
            constraint_zero_domain
                .at(constraint_zero_domain.size() - 2)
                .into_ef(),
            constraint_zero_domain
                .at(constraint_zero_domain.size() - 1)
                .into_ef(),
            point,
        );
        let num = constraint_value * selector;
        let denom = coset_vanishing(constraint_zero_domain, point);
        num / denom
    }

    ///boundary
    pub fn boundary_constraint_eval_quotient_by_mask<F: ExtensionOf<BaseField>>(
        log_size: u32,
        claim: M31,
        point: CirclePoint<F>,
        mask: &[F; 1],
    ) -> F {
        let constraint_zero_domain = Coset::subgroup(log_size);
        let p = constraint_zero_domain.at(constraint_zero_domain.size() - 1);
        let linear = F::one() + point.y * (claim - BaseField::one()) * p.y.inverse();

        let num = mask[0] - linear;
        let denom = pair_vanishing(p.into_ef(), CirclePoint::zero(), point);
        num / denom
    }
}

#[cfg(test)]
mod test {
    use stwo_prover::core::channel::{BWSSha256Channel, Channel};
    use stwo_prover::core::fields::m31::{BaseField, M31};
    use stwo_prover::core::fields::IntoSlice;
    use stwo_prover::core::prover::{prove, verify};
    use stwo_prover::core::vcs::bws_sha256_hash::BWSSha256Hasher;
    use stwo_prover::core::vcs::hasher::Hasher;
    use stwo_prover::examples::fibonacci::Fibonacci;

    #[test]
    fn test_fib_prove() {
        const FIB_LOG_SIZE: u32 = 5;
        let fib = Fibonacci::new(FIB_LOG_SIZE, M31::reduce(443693538));

        let trace = fib.get_trace();
        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        let proof = prove(&fib.air, channel, vec![trace]).unwrap();

        let channel =
            &mut BWSSha256Channel::new(BWSSha256Hasher::hash(BaseField::into_slice(&[fib
                .air
                .component
                .claim])));
        verify(proof, &fib.air, channel).unwrap()
    }
}
