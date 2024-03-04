use super::{
    math::{
        ffldl, ffsampling, gram, normalize_tree, ntru_gen, secret_key_from_bytes,
        secret_key_to_bytes, FalconFelt, FastFft, LdlTree, Polynomial,
    },
    ByteReader, ByteWriter, Deserializable, DeserializationError, FalconError, Felt, Rpo256,
    Serializable, Signature, Word, B0, MODULUS, N, SIGMA, SIG_L2_BOUND,
};
use crate::dsa::rpo_falcon512::{
    math::{compress_signature, pub_key_to_bytes},
    signature::hash_to_point,
    SIG_NONCE_LEN, SK_LEN,
};
use crate::utils::{collections::*, vec};
use num::Complex;
use num_complex::Complex64;
use rand::{thread_rng, Rng, RngCore};

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
    pub fn new(pk: Polynomial<FalconFelt>) -> Self {
        let pk_felts: Polynomial<Felt> = pk.into();
        let pk_digest = Rpo256::hash_elements(&pk_felts.coefficients).into();
        Self(pk_digest)
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

// SECRET KEY
// ================================================================================================

/// TODO: ADD DOCS
#[derive(Debug, Clone)]
pub struct SecretKey {
    secret_key: B0,
    tree: LdlTree,
}

#[allow(clippy::new_without_default)]
impl SecretKey {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Generates a secret key from OS-provided randomness.
    pub fn new() -> Self {
        Self::from_seed(thread_rng().gen())
    }

    /// Generates a secret_key from the provided seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let b0 = ntru_gen(N, seed);
        Self::from_b0(b0)
    }

    /// TODO: add docs
    fn from_b0(b0: B0) -> SecretKey {
        let b0_fft = b0.clone().map(|c| c.map(|cc| Complex64::new(*cc as f64, 0.0)).fft());

        let g0_fft = gram(b0_fft);
        let mut tree = ffldl(g0_fft);
        normalize_tree(&mut tree, SIGMA);
        Self { secret_key: b0, tree }
    }

    /// Derives the public key corresponding to this secret key.
    pub fn pub_key(&self) -> Polynomial<FalconFelt> {
        let f = self.secret_key[1].map(|&c| -FalconFelt::new(c));
        let f_ntt = f.fft();
        let g = self.secret_key[0].map(|&c| FalconFelt::new(c));
        let g_ntt = g.fft();
        let h_ntt = g_ntt.hadamard_div(&f_ntt);
        h_ntt.ifft()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the public key corresponding to this key pair.
    pub fn public_key(&self) -> PublicKey {
        // TODO: memoize public key commitment as computing it requires quite a bit of hashing.
        // expect() is fine here because we assume that the key pair was constructed correctly.
        PublicKey::new(self.pub_key())
    }

    // SIGNATURE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Signs a message with the secret key.
    ///
    /// # Errors
    /// Returns an error of signature generation fails.
    pub fn sign(&self, message: Word) -> Result<Signature, FalconError> {
        let mut rng = thread_rng();
        let mut nonce = [0u8; SIG_NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let c = hash_to_point(message, &nonce);
        let one_over_q = 1.0 / (MODULUS as f64);
        let c_over_q_fft = c.map(|cc| Complex::new(one_over_q * cc.value() as f64, 0.0)).fft();

        // B = [[FFT(g), -FFT(f)], [FFT(G), -FFT(F)]]
        let capital_f_fft = self.secret_key[3].map(|&i| Complex64::new(-i as f64, 0.0)).fft();
        let f_fft = self.secret_key[1].map(|&i| Complex64::new(-i as f64, 0.0)).fft();
        let capital_g_fft = self.secret_key[2].map(|&i| Complex64::new(i as f64, 0.0)).fft();
        let g_fft = self.secret_key[0].map(|&i| Complex64::new(i as f64, 0.0)).fft();
        let t0 = c_over_q_fft.hadamard_mul(&capital_f_fft);
        let t1 = -c_over_q_fft.hadamard_mul(&f_fft);

        let (s2, s2_coef) = loop {
            let bold_s = loop {
                let z = ffsampling(&(t0.clone(), t1.clone()), &self.tree, &mut rng);
                let t0_min_z0 = t0.clone() - z.0;
                let t1_min_z1 = t1.clone() - z.1;

                // s = (t-z) * B
                let s0 = t0_min_z0.hadamard_mul(&g_fft) + t1_min_z1.hadamard_mul(&capital_g_fft);
                let s1 = t0_min_z0.hadamard_mul(&f_fft) + t1_min_z1.hadamard_mul(&capital_f_fft);

                // compute the norm of (s0||s1) and note that they are in FFT representation
                let length_squared: f64 =
                    (s0.coefficients.iter().map(|a| (a * a.conj()).re).sum::<f64>()
                        + s1.coefficients.iter().map(|a| (a * a.conj()).re).sum::<f64>())
                        / (N as f64);

                if length_squared > (SIG_L2_BOUND as f64) {
                    continue;
                }

                break [s0, s1];
            };
            let s2 = bold_s[1].ifft();
            let s2_coef: [i16; N] = s2
                .coefficients
                .iter()
                .map(|a| a.re.round() as i16)
                .collect::<Vec<i16>>()
                .try_into()
                .expect("The number of coefficients should be equal to N");

            if let Some(s) = compress_signature(&s2_coef) {
                break (s, s2_coef);
            }
        };

        let header = 0x30 + 9;
        let mut sig = vec![header];
        sig.extend_from_slice(&nonce);
        sig.extend_from_slice(&s2);

        let pk_polynomial = self.pub_key();
        let sig_polynomial = s2_coef.to_vec().into();

        Ok(Signature {
            sig: sig
                .try_into()
                .expect("Signature compression step guarantees that this does not fail."),
            pk: pub_key_to_bytes(&pk_polynomial)?,
            pk_poly: pk_polynomial,
            sig_poly: sig_polynomial,
        })
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let buffer = secret_key_to_bytes(&self.secret_key);
        target.write_bytes(&buffer);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let sk: [u8; SK_LEN] = source.read_array()?;
        let b0 = secret_key_from_bytes(&sk).map_err(|_| DeserializationError::UnexpectedEOF)?;
        Ok(SecretKey::from_b0(b0))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{super::Felt, SecretKey, Word};
    use rand_utils::{rand_array, rand_vector};
    use winter_utils::{Deserializable, Serializable};

    #[test]
    fn test_falcon_verification() {
        // generate random keys
        let sk = SecretKey::new();
        let pk = sk.public_key();

        // test secret key serialization/deserialization
        let sk_bytes = sk.to_bytes();
        let sk = SecretKey::read_from_bytes(&sk_bytes).unwrap();

        // sign a random message
        let message: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        let signature = sk.sign(message);

        // make sure the signature verifies correctly
        assert!(pk.verify(message, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong message
        let message2: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        assert!(!pk.verify(message2, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong public key
        let sk2 = SecretKey::new();
        assert!(!sk2.public_key().verify(message, signature.as_ref().unwrap()))
    }

    #[test]
    fn test_falcon_verification_from_seed() {
        // generate keys from a random seed
        let seed: [u8; 32] = rand_array();
        let sk = SecretKey::from_seed(seed);
        let pk = sk.public_key();

        // test secret key serialization/deserialization
        let sk_bytes = sk.to_bytes();
        let sk = SecretKey::read_from_bytes(&sk_bytes).unwrap();

        // sign a random message
        let message: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        let signature = sk.sign(message);

        // make sure the signature verifies correctly
        assert!(pk.verify(message, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong message
        let message2: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        assert!(!pk.verify(message2, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong public key
        let keys2 = SecretKey::new();
        assert!(!keys2.public_key().verify(message, signature.as_ref().unwrap()))
    }
}
