#[cfg(test)]
mod test {
    use stwo_prover::core::fields::m31::M31;
    use stwo_prover::examples::fibonacci::Fibonacci;

    #[test]
    fn test_fib_prove() {
        const FIB_LOG_SIZE: u32 = 5;
        let fib = Fibonacci::new(FIB_LOG_SIZE, M31::reduce(443693538));

        let proof = fib.prove().unwrap();
        fib.verify(proof).unwrap();
    }
}
