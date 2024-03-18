use super::{
    math::{FalconFelt, FastFft, Polynomial},
    ByteReader, ByteWriter, Deserializable, DeserializationError, Felt, Serializable, Signature,
    Word, MODULUS,
};
use num::Complex;
use num_complex::Complex64;

mod public_key;
pub use public_key::{PubKeyPoly, PublicKey};

mod secret_key;
pub use secret_key::SecretKey;

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
    use super::{Felt, SecretKey, Word};
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
        let signature = sk.sign(message, &mut rng);

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
        let signature = sk.sign(message, &mut rng);

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
