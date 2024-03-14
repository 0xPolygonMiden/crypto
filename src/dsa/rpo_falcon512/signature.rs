use super::{
    keys::PubKeyPoly,
    math::{compress_signature, decompress_signature, FalconFelt, FastFft, Polynomial},
    ByteReader, ByteWriter, Deserializable, DeserializationError, Felt, HashToPoint, Nonce, Rpo256,
    Serializable, SignatureBytes, Word, SIG_HEADER_LEN, SIG_L2_BOUND, SIG_NONCE_LEN,
};
use crate::utils::string::*;

// FALCON SIGNATURE
// ================================================================================================

/// An RPO Falcon512 signature over a message.
///
/// The signature is a pair of polynomials (s1, s2) in (Z_p\[x\]/(phi))^2, where:
/// - p := 12289
/// - phi := x^512 + 1
/// - s1 = c - s2 * h
/// - h is a polynomial representing the public key and c is a polynomial that is the hash-to-point
///   of the message being signed.
///
/// The signature  verifies if and only if:
/// 1. s1 = c - s2 * h
/// 2. |s1|^2 + |s2|^2 <= SIG_L2_BOUND
///
/// where |.| is the norm.
///
/// [Signature] also includes the extended public key which is serialized as:
/// 1. 1 byte representing the log2(512) i.e., 9.
/// 2. 896 bytes for the public key. This is decoded into the `h` polynomial above.
///
/// The actual signature is serialized as:
/// 1. A header byte specifying the algorithm used to encode the coefficients of the `s2` polynomial
///    together with the degree of the irreducible polynomial phi.
///    The general format of this byte is 0b0cc1nnnn where:
///     a. cc is either 01 when the compressed encoding algorithm is used and 10 when the
///     uncompressed algorithm is used.
///     b. nnnn is log2(N) where N is the degree of the irreducible polynomial phi.
///    The current implementation works always with cc equal to 0b01 and nnnn equal to 0b1001 and
///    thus the header byte is always equal to 0b00111001.
/// 2. 40 bytes for the nonce.
/// 3. 625 bytes encoding the `s2` polynomial above.
///
/// The total size of the signature (including the extended public key) is 1563 bytes.
#[derive(Debug, Clone)]
pub struct Signature {
    h: PubKeyPoly,
    s2: Polynomial<FalconFelt>,
    nonce: Nonce,
    htp: HashToPoint,
}

impl Signature {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    pub fn new(
        h: PubKeyPoly,
        s2: Polynomial<FalconFelt>,
        nonce: Nonce,
        htp: HashToPoint,
    ) -> Signature {
        Self { h, s2, nonce, htp }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the public key polynomial h.
    pub fn pk_poly(&self) -> &Polynomial<FalconFelt> {
        &self.h
    }

    // Returns the polynomial representation of the signature in Z_p[x]/(phi).
    pub fn sig_poly(&self) -> &Polynomial<FalconFelt> {
        &self.s2
    }

    /// Returns the nonce component of the signature.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Returns the hahs-to-point algorithm used to generate the signature.
    pub fn hash_to_point(&self) -> HashToPoint {
        self.htp
    }

    // SIGNATURE VERIFICATION
    // --------------------------------------------------------------------------------------------

    /// Returns true if this signature is a valid signature for the specified message generated
    /// against secret key matching the specified public key commitment.
    pub fn verify(&self, message: Word, pubkey_com: Word) -> bool {
        let h: Polynomial<Felt> = self.pk_poly().into();
        let h_digest: Word = Rpo256::hash_elements(&h.coefficients).into();
        if h_digest != pubkey_com {
            return false;
        }

        let c = self.htp.hash(message, &self.nonce);

        let s2_fft = self.s2.fft();
        let h_fft = self.h.fft();
        let c_fft = c.fft();

        // s1 = c - s2 * h;
        let s1_fft = c_fft - s2_fft.hadamard_mul(&h_fft);
        let s1 = s1_fft.ifft();

        let length_squared_s1 = s1.norm_squared();
        let length_squared_s2 = self.s2.norm_squared();
        let length_squared = length_squared_s1 + length_squared_s2;
        length_squared < SIG_L2_BOUND
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // encode public key
        target.write(&self.h);

        // encode signature
        let sig_coeff: Vec<i16> = self.s2.coefficients.iter().map(|a| a.balanced_value()).collect();
        let sk_bytes = compress_signature(&sig_coeff).unwrap();
        let header = vec![0x30 + 9];
        let htp = vec![self.hash_to_point() as u8];
        target.write_bytes(&header);
        target.write_bytes(self.nonce.as_bytes());
        target.write_bytes(&sk_bytes);
        target.write_bytes(&htp);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // decode public key
        let pk: PubKeyPoly = source.read()?;

        let sig_bytes: SignatureBytes = source.read_array()?;
        let htp: [u8; 1] = source.read_array()?;

        // decode signature
        let nonce_bytes = (&sig_bytes[SIG_HEADER_LEN..SIG_HEADER_LEN + SIG_NONCE_LEN])
            .try_into()
            .expect("should not fail");
        let nonce = Nonce::new(nonce_bytes);
        let s2 = if let Ok(poly) = decompress_signature(&sig_bytes) {
            poly
        } else {
            return Err(DeserializationError::InvalidValue(
                "Invalid signature encoding".to_string(),
            ));
        };
        let htp = match htp[0] {
            0 => HashToPoint::Rpo256,
            1 => HashToPoint::Shake256,
            _ => {
                Err(DeserializationError::InvalidValue("Invalid hash-to-point variant".to_owned()))?
            }
        };

        Ok(Self::new(pk, s2, nonce, htp))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{super::SecretKey, *};
    use rand::thread_rng;

    #[test]
    fn test_serialization_round_trip() {
        let key = SecretKey::new();
        let mut rng = thread_rng();
        let signature = key.sign(Word::default(), &mut rng, HashToPoint::Rpo256).unwrap();
        let serialized = signature.to_bytes();
        let deserialized = Signature::read_from_bytes(&serialized).unwrap();
        assert_eq!(signature.sig_poly(), deserialized.sig_poly());
        assert_eq!(signature.pk_poly(), deserialized.pk_poly());
    }
}
