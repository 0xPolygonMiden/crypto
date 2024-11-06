mod signature;
pub use signature::{PublicKey, SecretKey, Signature};

mod stark;

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::SecretKey;

    #[test]
    fn test_signature() {
        use rand_utils::rand_array;

        let sk = SecretKey::new();

        let message = rand_array();
        let signature = sk.sign(message);

        let pk = sk.compute_public_key();
        assert!(pk.verify(message, &signature))
    }
}
