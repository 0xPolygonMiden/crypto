mod signature;
pub use signature::{PublicKey, SecretKey, Signature};

mod stark;
pub use stark::{PublicInputs, RescueAir};

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::SecretKey;
    use crate::Word;

    #[test]
    fn test_signature() {
        let sk = SecretKey::new(Word::default());

        let message = Word::default();
        let signature = sk.sign(message);
        let pk = sk.public_key();
        assert!(pk.verify(message, &signature))
    }
}
