#[cfg(test)]
mod test {
    use stwo_fork::core::prover::{prove, verify};
    use stwo_prover::core::channel::{Blake2sChannel, Channel};
    use stwo_prover::core::fields::m31::{BaseField, M31};
    use stwo_prover::core::fields::IntoSlice;
    use stwo_prover::core::vcs::blake2_hash::Blake2sHasher;
    use stwo_prover::core::vcs::hasher::Hasher;
    use stwo_prover::examples::fibonacci::Fibonacci;

    #[test]
    fn test_fib_prove() {
        const FIB_LOG_SIZE: u32 = 5;
        let fib = Fibonacci::new(FIB_LOG_SIZE, M31::reduce(443693538));

        let trace = fib.get_trace();
        let channel = &mut Blake2sChannel::new(Blake2sHasher::hash(BaseField::into_slice(&[fib
            .air
            .component
            .claim])));
        let proof = prove(&fib.air, channel, vec![trace]).unwrap();

        let channel = &mut Blake2sChannel::new(Blake2sHasher::hash(BaseField::into_slice(&[fib
            .air
            .component
            .claim])));
        verify(proof, &fib.air, channel).unwrap()
    }
}
