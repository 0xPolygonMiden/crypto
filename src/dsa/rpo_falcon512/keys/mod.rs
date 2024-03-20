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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{Felt, SecretKey, Word};
    use rand::rngs::OsRng;
    use winter_utils::{Deserializable, Serializable};

    #[test]
    fn test_falcon_verification() {
        // generate random keys
        let sk = SecretKey::new();
        let pk = sk.public_key();

        // test secret key serialization/deserialization
        let mut buffer = vec![];
        sk.write_into(&mut buffer);
        let sk = SecretKey::read_from_bytes(&buffer).unwrap();

        // sign a random message
        let message: Word =
            rand_utils::rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        let mut rng = OsRng;
        let signature = sk.sign(message, &mut rng);

        // make sure the signature verifies correctly
        assert!(pk.verify(message, &signature));

        // a signature should not verify against a wrong message
        let message2: Word =
            rand_utils::rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        assert!(!pk.verify(message2, &signature));

        // a signature should not verify against a wrong public key
        let sk2 = SecretKey::new();
        assert!(!sk2.public_key().verify(message, &signature))
    }
}
