use alloc::string::ToString;
use core::cell::OnceCell;

use super::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Felt, NonceBytes, NonceElements,
    Polynomial, PublicKeyBytes, Rpo256, Serializable, SignatureBytes, Word, MODULUS, N,
    SIG_L2_BOUND, ZERO,
};

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
    pub(super) pk: PublicKeyBytes,
    pub(super) sig: SignatureBytes,

    // Cached polynomial decoding for public key and signatures
    pub(super) pk_polynomial: OnceCell<Polynomial>,
    pub(super) sig_polynomial: OnceCell<Polynomial>,
}

impl Signature {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the public key polynomial h.
    pub fn pub_key_poly(&self) -> Polynomial {
        *self.pk_polynomial.get_or_init(|| {
            // we assume that the signature was constructed with a valid public key, and thus
            // expect() is OK here.
            Polynomial::from_pub_key(&self.pk).expect("invalid public key")
        })
    }

    /// Returns the nonce component of the signature represented as field elements.
    ///
    /// Nonce bytes are converted to field elements by taking consecutive 5 byte chunks
    /// of the nonce and interpreting them as field elements.
    pub fn nonce(&self) -> NonceElements {
        // we assume that the signature was constructed with a valid signature, and thus
        // expect() is OK here.
        let nonce = self.sig[1..41].try_into().expect("invalid signature");
        decode_nonce(nonce)
    }

    // Returns the polynomial representation of the signature in Z_p[x]/(phi).
    pub fn sig_poly(&self) -> Polynomial {
        *self.sig_polynomial.get_or_init(|| {
            // we assume that the signature was constructed with a valid signature, and thus
            // expect() is OK here.
            Polynomial::from_signature(&self.sig).expect("invalid signature")
        })
    }

    // HASH-TO-POINT
    // --------------------------------------------------------------------------------------------

    /// Returns a polynomial in Z_p\[x\]/(phi) representing the hash of the provided message.
    pub fn hash_to_point(&self, message: Word) -> Polynomial {
        hash_to_point(message, &self.nonce())
    }

    // SIGNATURE VERIFICATION
    // --------------------------------------------------------------------------------------------
    /// Returns true if this signature is a valid signature for the specified message generated
    /// against key pair matching the specified public key commitment.
    pub fn verify(&self, message: Word, pubkey_com: Word) -> bool {
        // Make sure the expanded public key matches the provided public key commitment
        let h = self.pub_key_poly();
        let h_digest: Word = Rpo256::hash_elements(&h.to_elements()).into();
        if h_digest != pubkey_com {
            return false;
        }

        // Make sure the signature is valid
        let s2 = self.sig_poly();
        let c = self.hash_to_point(message);

        let s1 = c - s2 * h;

        let sq_norm = s1.sq_norm() + s2.sq_norm();
        sq_norm <= SIG_L2_BOUND
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.pk);
        target.write_bytes(&self.sig);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let pk: PublicKeyBytes = source.read_array()?;
        let sig: SignatureBytes = source.read_array()?;

        // make sure public key and signature can be decoded correctly
        let pk_polynomial = Polynomial::from_pub_key(&pk)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?
            .into();
        let sig_polynomial = Polynomial::from_signature(&sig)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?
            .into();

        Ok(Self { pk, sig, pk_polynomial, sig_polynomial })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a polynomial in Z_p[x]/(phi) representing the hash of the provided message and
/// nonce.
fn hash_to_point(message: Word, nonce: &NonceElements) -> Polynomial {
    let mut state = [ZERO; Rpo256::STATE_WIDTH];

    // absorb the nonce into the state
    for (&n, s) in nonce.iter().zip(state[Rpo256::RATE_RANGE].iter_mut()) {
        *s = n;
    }
    Rpo256::apply_permutation(&mut state);

    // absorb message into the state
    for (&m, s) in message.iter().zip(state[Rpo256::RATE_RANGE].iter_mut()) {
        *s = m;
    }

    // squeeze the coefficients of the polynomial
    let mut i = 0;
    let mut res = [0_u16; N];
    for _ in 0..64 {
        Rpo256::apply_permutation(&mut state);
        for a in &state[Rpo256::RATE_RANGE] {
            res[i] = (a.as_int() % MODULUS as u64) as u16;
            i += 1;
        }
    }

    // using the raw constructor is OK here because we reduce all coefficients by the modulus above
    unsafe { Polynomial::new(res) }
}

/// Converts byte representation of the nonce into field element representation.
fn decode_nonce(nonce: &NonceBytes) -> NonceElements {
    let mut buffer = [0_u8; 8];
    let mut result = [ZERO; 8];
    for (i, bytes) in nonce.chunks(5).enumerate() {
        buffer[..5].copy_from_slice(bytes);
        // we can safely (without overflow) create a new Felt from u64 value here since this value
        // contains at most 5 bytes
        result[i] = Felt::new(u64::from_le_bytes(buffer));
    }

    result
}

// TESTS
// ================================================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    use core::ffi::c_void;
    use rand_utils::rand_vector;

    use super::{
        super::{ffi::*, KeyPair},
        *,
    };

    // Wrappers for unsafe functions
    impl Rpo128Context {
        /// Initializes the RPO state.
        pub fn init() -> Self {
            let mut ctx = Rpo128Context { content: [0u64; 13] };
            unsafe {
                rpo128_init(&mut ctx as *mut Rpo128Context);
            }
            ctx
        }

        /// Absorbs data into the RPO state.
        pub fn absorb(&mut self, data: &[u8]) {
            unsafe {
                rpo128_absorb(
                    self as *mut Rpo128Context,
                    data.as_ptr() as *const c_void,
                    data.len(),
                )
            }
        }

        /// Finalizes the RPO state to prepare for squeezing.
        pub fn finalize(&mut self) {
            unsafe { rpo128_finalize(self as *mut Rpo128Context) }
        }
    }

    #[test]
    fn test_hash_to_point() {
        // Create a random message and transform it into a u8 vector
        let msg_felts: Word = rand_vector::<Felt>(4).try_into().unwrap();
        let msg_bytes = msg_felts
            .iter()
            .flat_map(|e| e.as_int().to_le_bytes())
            .collect::<alloc::vec::Vec<_>>();

        // Create a nonce i.e. a [u8; 40] array and pack into a [Felt; 8] array.
        let nonce: [u8; 40] = rand_vector::<u8>(40).try_into().unwrap();

        let mut buffer = [0_u8; 64];
        for i in 0..8 {
            buffer[8 * i] = nonce[5 * i];
            buffer[8 * i + 1] = nonce[5 * i + 1];
            buffer[8 * i + 2] = nonce[5 * i + 2];
            buffer[8 * i + 3] = nonce[5 * i + 3];
            buffer[8 * i + 4] = nonce[5 * i + 4];
        }

        // Initialize the RPO state
        let mut rng = Rpo128Context::init();

        // Absorb the nonce and message into the RPO state
        rng.absorb(&buffer);
        rng.absorb(&msg_bytes);
        rng.finalize();

        // Generate the coefficients of the hash-to-point polynomial.
        let mut res: [u16; N] = [0; N];

        unsafe {
            PQCLEAN_FALCON512_CLEAN_hash_to_point_rpo(
                &mut rng as *mut Rpo128Context,
                res.as_mut_ptr(),
                9,
            );
        }

        // Check that the coefficients are correct
        let nonce = decode_nonce(&nonce);
        assert_eq!(res, hash_to_point(msg_felts, &nonce).inner());
    }

    #[test]
    fn test_serialization_round_trip() {
        let key = KeyPair::new().unwrap();
        let signature = key.sign(Word::default()).unwrap();
        let serialized = signature.to_bytes();
        let deserialized = Signature::read_from_bytes(&serialized).unwrap();
        assert_eq!(signature.sig_poly(), deserialized.sig_poly());
        assert_eq!(signature.pub_key_poly(), deserialized.pub_key_poly());
    }
}
