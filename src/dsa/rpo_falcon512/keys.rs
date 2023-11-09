use super::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, FalconError, Polynomial,
    PublicKeyBytes, Rpo256, SecretKeyBytes, Serializable, Signature, Word,
};

#[cfg(feature = "std")]
use super::{ffi, NonceBytes, StarkField, NONCE_LEN, PK_LEN, SIG_LEN, SK_LEN};

// PUBLIC KEY
// ================================================================================================

/// A public key for verifying signatures.
///
/// The public key is a [Word] (i.e., 4 field elements) that is the hash of the coefficients of
/// the polynomial representing the raw bytes of the expanded public key.
///
/// For Falcon-512, the first byte of the expanded public key is always equal to log2(512) i.e., 9.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicKey(Word);

impl PublicKey {
    /// Returns a new [PublicKey] which is a commitment to the provided expanded public key.
    ///
    /// # Errors
    /// Returns an error if the decoding of the public key fails.
    pub fn new(pk: PublicKeyBytes) -> Result<Self, FalconError> {
        let h = Polynomial::from_pub_key(&pk)?;
        let pk_felts = h.to_elements();
        let pk_digest = Rpo256::hash_elements(&pk_felts).into();
        Ok(Self(pk_digest))
    }

    /// Verifies the provided signature against provided message and this public key.
    pub fn verify(&self, message: Word, signature: &Signature) -> bool {
        signature.verify(message, self.0)
    }
}

impl From<PublicKey> for Word {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}

// KEY PAIR
// ================================================================================================

/// A key pair (public and secret keys) for signing messages.
///
/// The secret key is a byte array of length [PK_LEN].
/// The public key is a byte array of length [SK_LEN].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyPair {
    public_key: PublicKeyBytes,
    secret_key: SecretKeyBytes,
}

#[allow(clippy::new_without_default)]
impl KeyPair {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Generates a (public_key, secret_key) key pair from OS-provided randomness.
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    #[cfg(feature = "std")]
    pub fn new() -> Result<Self, FalconError> {
        let mut public_key = [0u8; PK_LEN];
        let mut secret_key = [0u8; SK_LEN];

        let res = unsafe {
            ffi::PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_rpo(
                public_key.as_mut_ptr(),
                secret_key.as_mut_ptr(),
            )
        };

        if res == 0 {
            Ok(Self { public_key, secret_key })
        } else {
            Err(FalconError::KeyGenerationFailed)
        }
    }

    /// Generates a (public_key, secret_key) key pair from the provided seed.
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    #[cfg(feature = "std")]
    pub fn from_seed(seed: &NonceBytes) -> Result<Self, FalconError> {
        let mut public_key = [0u8; PK_LEN];
        let mut secret_key = [0u8; SK_LEN];

        let res = unsafe {
            ffi::PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_from_seed_rpo(
                public_key.as_mut_ptr(),
                secret_key.as_mut_ptr(),
                seed.as_ptr(),
            )
        };

        if res == 0 {
            Ok(Self { public_key, secret_key })
        } else {
            Err(FalconError::KeyGenerationFailed)
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the public key corresponding to this key pair.
    pub fn public_key(&self) -> PublicKey {
        // TODO: memoize public key commitment as computing it requires quite a bit of hashing.
        // expect() is fine here because we assume that the key pair was constructed correctly.
        PublicKey::new(self.public_key).expect("invalid key pair")
    }

    /// Returns the expanded public key corresponding to this key pair.
    pub fn expanded_public_key(&self) -> PublicKeyBytes {
        self.public_key
    }

    // SIGNATURE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Signs a message with a secret key and a seed.
    ///
    /// # Errors
    /// Returns an error of signature generation fails.
    #[cfg(feature = "std")]
    pub fn sign(&self, message: Word) -> Result<Signature, FalconError> {
        let msg = message.iter().flat_map(|e| e.as_int().to_le_bytes()).collect::<Vec<_>>();
        let msg_len = msg.len();
        let mut sig = [0_u8; SIG_LEN + NONCE_LEN];
        let mut sig_len: usize = 0;

        let res = unsafe {
            ffi::PQCLEAN_FALCON512_CLEAN_crypto_sign_signature_rpo(
                sig.as_mut_ptr(),
                &mut sig_len as *mut usize,
                msg.as_ptr(),
                msg_len,
                self.secret_key.as_ptr(),
            )
        };

        if res == 0 {
            Ok(Signature {
                sig,
                pk: self.public_key,
                pk_polynomial: Default::default(),
                sig_polynomial: Default::default(),
            })
        } else {
            Err(FalconError::SigGenerationFailed)
        }
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for KeyPair {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.public_key);
        target.write_bytes(&self.secret_key);
    }
}

impl Deserializable for KeyPair {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let public_key: PublicKeyBytes = source.read_array()?;
        let secret_key: SecretKeyBytes = source.read_array()?;
        Ok(Self { public_key, secret_key })
    }
}

// TESTS
// ================================================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{super::Felt, KeyPair, NonceBytes, Word};
    use rand_utils::{rand_array, rand_vector};

    #[test]
    fn test_falcon_verification() {
        // generate random keys
        let keys = KeyPair::new().unwrap();
        let pk = keys.public_key();

        // sign a random message
        let message: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        let signature = keys.sign(message);

        // make sure the signature verifies correctly
        assert!(pk.verify(message, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong message
        let message2: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        assert!(!pk.verify(message2, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong public key
        let keys2 = KeyPair::new().unwrap();
        assert!(!keys2.public_key().verify(message, signature.as_ref().unwrap()))
    }

    #[test]
    fn test_falcon_verification_from_seed() {
        // generate keys from a random seed
        let seed: NonceBytes = rand_array();
        let keys = KeyPair::from_seed(&seed).unwrap();
        let pk = keys.public_key();

        // sign a random message
        let message: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        let signature = keys.sign(message);

        // make sure the signature verifies correctly
        assert!(pk.verify(message, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong message
        let message2: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        assert!(!pk.verify(message2, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong public key
        let keys2 = KeyPair::new().unwrap();
        assert!(!keys2.public_key().verify(message, signature.as_ref().unwrap()))
    }
}
