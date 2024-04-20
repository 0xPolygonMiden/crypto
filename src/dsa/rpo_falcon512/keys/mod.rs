use super::{
    math::{FalconFelt, Polynomial},
    ByteReader, ByteWriter, Deserializable, DeserializationError, Felt, Serializable, Signature,
    Word,
};

mod public_key;
pub use public_key::{PubKeyPoly, PublicKey};

mod secret_key;
pub use secret_key::SecretKey;

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::{dsa::rpo_falcon512::SecretKey, Word, ONE};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use winter_math::FieldElement;
    use winter_utils::{Deserializable, Serializable};

    #[test]
    fn test_falcon_verification() {
        let mut rng = ChaCha20Rng::from_entropy();

        // generate random keys
        let sk = SecretKey::new();
        let pk = sk.public_key();

        // test secret key serialization/deserialization
        let mut buffer = vec![];
        sk.write_into(&mut buffer);
        let sk_deserialized = SecretKey::read_from_bytes(&buffer).unwrap();
        assert_eq!(sk.short_lattice_basis(), sk_deserialized.short_lattice_basis());

        // sign a random message
        let message: Word = [ONE; 4];
        let signature = sk.sign_with_rng(message, &mut rng);

        // make sure the signature verifies correctly
        assert!(pk.verify(message, &signature));

        // a signature should not verify against a wrong message
        let message2: Word = [ONE.double(); 4];
        assert!(!pk.verify(message2, &signature));

        // a signature should not verify against a wrong public key
        let sk2 = SecretKey::with_rng(&mut rng);
        assert!(!sk2.public_key().verify(message, &signature))
    }
}
