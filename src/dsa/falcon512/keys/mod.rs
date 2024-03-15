use super::{
    math::{ffsampling, FalconFelt, FastFft, Polynomial},
    signature::SignaturePoly,
    ByteReader, ByteWriter, Deserializable, DeserializationError, FalconError, Felt, HashToPoint,
    Nonce, Serializable, Signature, Word, MODULUS, N, SIG_L2_BOUND, SIG_NONCE_LEN,
};
use num::Complex;
use num_complex::Complex64;
use rand::{thread_rng, Rng};

mod public_key;
pub use public_key::{PubKeyPoly, PublicKey};

mod secret_key;
pub use secret_key::SecretKey;

// KEY PAIR
// ================================================================================================

/// A key pair is composed of a [SecretKey] and its associated [PubKeyPoly].
pub struct KeyPair {
    secret_key: SecretKey,
    public_key: PubKeyPoly,
}

#[allow(clippy::new_without_default)]
impl KeyPair {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a key pair from OS-provided randomness.
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        Self::from_seed(thread_rng().gen())
    }

    /// Creates a key pair from a seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret_key = SecretKey::from_seed(seed);
        let public_key = secret_key.compute_pub_key_poly();
        Self { secret_key, public_key }
    }

    // SIGNATURE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Signs a message with the key pair.
    ///
    /// Takes a randomness generator implementing `Rng` and a hash-to-point algorithm `HashToPoint`
    /// as parameters. It outputs a signature `Signature`.
    ///
    /// # Errors
    /// Returns an error of signature generation fails.
    pub fn sign<R: Rng>(
        &self,
        message: Word,
        rng: &mut R,
        htp: HashToPoint,
    ) -> Result<Signature, FalconError> {
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::new(nonce_bytes);

        let c = htp.hash(message, &nonce);
        let one_over_q = 1.0 / (MODULUS as f64);
        let c_over_q_fft = c.map(|cc| Complex::new(one_over_q * cc.value() as f64, 0.0)).fft();

        // B = [[FFT(g), -FFT(f)], [FFT(G), -FFT(F)]]
        let [g_fft, minus_f_fft, big_g_fft, minus_big_f_fft] =
            to_complex_fft(self.secret_key.short_lattice_basis());
        let t0 = c_over_q_fft.hadamard_mul(&minus_big_f_fft);
        let t1 = -c_over_q_fft.hadamard_mul(&minus_f_fft);

        let s2 = loop {
            let bold_s = loop {
                let z = ffsampling(&(t0.clone(), t1.clone()), self.secret_key.tree(), rng);
                let t0_min_z0 = t0.clone() - z.0;
                let t1_min_z1 = t1.clone() - z.1;

                // s = (t-z) * B
                let s0 = t0_min_z0.hadamard_mul(&g_fft) + t1_min_z1.hadamard_mul(&big_g_fft);
                let s1 =
                    t0_min_z0.hadamard_mul(&minus_f_fft) + t1_min_z1.hadamard_mul(&minus_big_f_fft);

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

            if let Ok(s2) = SignaturePoly::try_from(&s2_coef) {
                break s2;
            }
        };
        let pk = self.public_key.clone();
        Ok(Signature::new(pk, s2, nonce, htp))
    }
}

// HELPER
// ================================================================================================

/// Computes the complex FFT of the secret key polynomials.
fn to_complex_fft(basis: &[Polynomial<i16>; 4]) -> [Polynomial<Complex<f64>>; 4] {
    let [g, f, big_g, big_f] = basis.clone();
    let g_fft = g.map(|cc| Complex64::new(*cc as f64, 0.0)).fft();
    let minus_f_fft = f.map(|cc| -Complex64::new(*cc as f64, 0.0)).fft();
    let big_g_fft = big_g.map(|cc| Complex64::new(*cc as f64, 0.0)).fft();
    let minus_big_f_fft = big_f.map(|cc| -Complex64::new(*cc as f64, 0.0)).fft();
    [g_fft, minus_f_fft, big_g_fft, minus_big_f_fft]
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::dsa::falcon512::{keys::KeyPair, PublicKey};

    use super::{super::HashToPoint, Felt, SecretKey, Word};
    use rand::thread_rng;
    use rand_utils::{rand_array, rand_vector};
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
        let message: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        let mut rng = thread_rng();
        let signature = sk.sign(message, &mut rng, HashToPoint::Rpo256);

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
        let mut rng = thread_rng();
        let signature = sk.sign(message, &mut rng, HashToPoint::Rpo256);

        // make sure the signature verifies correctly
        assert!(pk.verify(message, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong message
        let message2: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        assert!(!pk.verify(message2, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong public key
        let keys2 = SecretKey::new();
        assert!(!keys2.public_key().verify(message, signature.as_ref().unwrap()))
    }

    #[test]
    fn test_falcon_verification_key_pair() {
        // generate a random key pair
        let key_pair = KeyPair::new();

        // sign a random message
        let message: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        let mut rng = thread_rng();
        let signature = key_pair.sign(message, &mut rng, HashToPoint::Rpo256);

        // make sure the signature verifies correctly
        let pk: PublicKey = key_pair.public_key.into();
        assert!(pk.verify(message, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong message
        let message2: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        assert!(!pk.verify(message2, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong public key
        let sk2 = SecretKey::new();
        assert!(!sk2.public_key().verify(message, signature.as_ref().unwrap()))
    }

    #[test]
    fn test_falcon_verification_key_pair_from_seed() {
        // generate keys from a random seed
        let seed: [u8; 32] = rand_array();
        let key_pair = KeyPair::from_seed(seed);

        // sign a random message
        let message: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        let mut rng = thread_rng();
        let signature = key_pair.sign(message, &mut rng, HashToPoint::Rpo256);

        // make sure the signature verifies correctly
        let pk: PublicKey = key_pair.public_key.into();
        assert!(pk.verify(message, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong message
        let message2: Word = rand_vector::<Felt>(4).try_into().expect("Should not fail.");
        assert!(!pk.verify(message2, signature.as_ref().unwrap()));

        // a signature should not verify against a wrong public key
        let keys2 = SecretKey::new();
        assert!(!keys2.public_key().verify(message, signature.as_ref().unwrap()))
    }
}
