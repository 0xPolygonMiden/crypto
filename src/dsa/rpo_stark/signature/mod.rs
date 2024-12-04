use rand::Rng;
use winter_math::fields::f64::BaseElement;
use winter_prover::Proof;
use winter_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Randomizable, Serializable,
};
use winterfell::{FieldExtension, ProofOptions};

use super::stark::compute_rpo_image;
use crate::{dsa::rpo_stark::stark::RpoSignatureScheme, hash::rpo::Rpo256, Word, ZERO};

// CONSTANTS
// ================================================================================================

/// Specifies the parameters of the STARK underlying the signature scheme.
pub const PROOF_OPTIONS: ProofOptions =
    ProofOptions::new(30, 8, 12, FieldExtension::Quadratic, 4, 7, true);

// PUBLIC KEY
// ================================================================================================

/// A public key for verifying signatures.
///
/// The public key is a [Word] (i.e., 4 field elements) that is the hash of the secret key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(Word);

impl PublicKey {
    pub fn inner(&self) -> Word {
        self.0
    }
}

impl PublicKey {
    /// Verifies the provided signature against provided message and this public key.
    pub fn verify(&self, message: Word, signature: &Signature) -> bool {
        signature.verify(message, *self)
    }
}

// SECRET KEY
// ================================================================================================

/// A secret key for generating signatures.
///
/// The secret key is a [Word] (i.e., 4 field elements).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretKey(Word);

impl SecretKey {
    /// Generates a secret key from OS-provided randomness.
    #[cfg(feature = "std")]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        use rand::{rngs::StdRng, SeedableRng};

        let mut rng = StdRng::from_entropy();
        Self::with_rng(&mut rng)
    }

    /// Generates a secret key from a [Word].
    pub fn from_word(sk: Word) -> Self {
        Self(sk)
    }

    /// Generates a secret_key using the provided random number generator `Rng`.
    pub fn with_rng<R: Rng>(rng: &mut R) -> Self {
        let mut sk = [ZERO; 4];

        let mut dest = vec![0_u8; 8];
        for s in sk.iter_mut() {
            rng.fill_bytes(&mut dest);
            *s = BaseElement::from_random_bytes(&dest).expect("");
        }

        Self(sk)
    }

    /// Computes the public key corresponding to this secret key.
    pub fn compute_public_key(&self) -> PublicKey {
        let pk = compute_rpo_image(self.0);
        PublicKey(pk)
    }

    /// Signs a message with this secret key.
    pub fn sign(&self, message: Word) -> Signature {
        let signature: RpoSignatureScheme<Rpo256> = RpoSignatureScheme::new(PROOF_OPTIONS);
        let proof = signature.sign(self.0, message);
        Signature { proof }
    }
}

// SIGNATURE
// ================================================================================================

/// An RPO STARK-based signature over a message.
///
/// The signature is a STARK proof of knowledge of a pre-image given an image where the map is
/// the RPO permutation, the pre-image is the secret key and the image is the public key.
/// The current implementation follows the description in [1] in the unique decoding regime where
/// it is argued that for the parameter set `PROOF_OPTIONS` the signature achieves $113$ bits of
/// average-case existential unforgeability security against $2^{113}$-query bound adversaries
/// that can obtain up to $2^{64}$ signatures under the same public key.
///
/// [1]: https://eprint.iacr.org/2024/1553
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    proof: Proof,
}

impl Signature {
    pub fn inner(&self) -> Proof {
        self.proof.clone()
    }
    /// Returns true if this signature is a valid signature for the specified message generated
    /// against the secret key matching the specified public key commitment.
    pub fn verify(&self, message: Word, pk: PublicKey) -> bool {
        let signature: RpoSignatureScheme<Rpo256> = RpoSignatureScheme::new(PROOF_OPTIONS);

        let res = signature.verify(pk.inner(), message, self.proof.clone());
        res.is_ok()
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for PublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let pk = <Word>::read_from(source)?;
        Ok(Self(pk))
    }
}

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let sk = <Word>::read_from(source)?;
        Ok(Self(sk))
    }
}

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.proof.write_into(target);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof = Proof::read_from(source)?;
        Ok(Self { proof })
    }
}
