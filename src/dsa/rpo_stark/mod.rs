mod signature;
pub use signature::{PublicKey, SecretKey, Signature};

mod stark;

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::SecretKey;

    #[test]
    fn test_signature() {
        use rand_utils::rand_array;

        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let sk = SecretKey::with_rng(&mut rng);

        let message = rand_array();
        let signature = sk.sign(message);

        let pk = sk.compute_public_key();
        assert!(pk.verify(message, &signature))
    }
}
