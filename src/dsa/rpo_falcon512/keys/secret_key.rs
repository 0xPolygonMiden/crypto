use super::{
    super::{
        math::{
            decode_i8, encode_i8, ffldl, ffsampling, gram, normalize_tree, FalconFelt, FastFft,
            LdlTree, Polynomial,
        },
        signature::SignaturePoly,
        ByteReader, ByteWriter, Deserializable, DeserializationError, Nonce, Serializable,
        ShortLatticeBasis, Signature, Word, MODULUS, N, SIGMA, SIG_L2_BOUND,
    },
    PubKeyPoly, PublicKey,
};
use crate::dsa::rpo_falcon512::{
    hash_to_point::hash_to_point_rpo256, math::ntru_gen, SIG_NONCE_LEN, SK_LEN,
};
use alloc::{string::ToString, vec::Vec};
use num::{Complex, Zero};
use num_complex::Complex64;
use rand::{rngs::OsRng, Rng, RngCore};

//#[cfg(all(feature = "std", feature = "std_rng"))]

// CONSTANTS
// ================================================================================================

const WIDTH_BIG_POLY_COEFFICIENT: usize = 8;
const WIDTH_SMALL_POLY_COEFFICIENT: usize = 6;

// SECRET KEY
// ================================================================================================

/// The secret key is a quadruple [[g, -f], [G, -F]] of polynomials with integer coefficients. Each
/// polynomial is of degree at most N = 512 and computations with these polynomials is done modulo
/// the monic irreducible polynomial ϕ = x^N + 1. The secret key is a basis for a lattice and has
/// the property of being short with respect to a certain norm and an upper bound appropriate for
/// a given security parameter. The public key on the other hand is another basis for the same
/// lattice and can be described by a single polynomial h with integer coefficients modulo ϕ.
/// The two keys are related by the following relation:
///
/// 1. h = g /f [mod ϕ][mod p]
/// 2. f.G - g.F = p [mod ϕ]
///
/// where p = 12289 is the Falcon prime. Equation 2 is called the NTRU equation.
/// The secret key is generated by first sampling a random pair (f, g) of polynomials using
/// an appropriate distribution that yields short but not too short polynomials with integer
/// coefficients modulo ϕ. The NTRU equation is then used to find a matching pair (F, G).
/// The public key is then derived from the secret key using equation 2.
///
/// To allow for fast signature generation, the secret key is pre-processed into a more suitable
/// form, called the LDL tree, and this allows for fast sampling of short vectors in the lattice
/// using Fast Fourier sampling during signature generation (ffSampling algorithm 11 in [1]).
///
/// [1]: https://falcon-sign.info/falcon.pdf
#[derive(Debug, Clone)]
pub struct SecretKey {
    secret_key: ShortLatticeBasis,
    tree: LdlTree,
}

#[allow(clippy::new_without_default)]
impl SecretKey {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Generates a secret key from OS-provided randomness.
    pub fn new() -> Self {
        let mut seed: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut seed);
        //let rng: rand::rngs::StdRng = rand::SeedableRng::from_seed(seed);
        Self::with_rng(&mut OsRng)
    }

    /// Generates a secret_key using the provided random number generator `Rng`.
    pub fn with_rng<R: Rng>(rng: &mut R) -> Self {
        let basis = ntru_gen(N, rng);
        Self::from_short_lattice_basis(basis)
    }

    /// Given a short basis [[g, -f], [G, -F]], computes the normalized LDL tree i.e., Falcon tree.
    fn from_short_lattice_basis(basis: ShortLatticeBasis) -> SecretKey {
        // FFT each polynomial of the short basis.
        let basis_fft = to_complex_fft(&basis);
        // compute the Gram matrix.
        let gram_fft = gram(basis_fft);
        // construct the LDL tree of the Gram matrix.
        let mut tree = ffldl(gram_fft);
        // normalize the leaves of the LDL tree.
        normalize_tree(&mut tree, SIGMA);
        Self { secret_key: basis, tree }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the polynomials of the short lattice basis of this secret key.
    pub fn short_lattice_basis(&self) -> &ShortLatticeBasis {
        &self.secret_key
    }

    /// Returns the public key corresponding to this secret key.
    pub fn public_key(&self) -> PublicKey {
        self.compute_pub_key_poly().into()
    }

    /// Returns the LDL tree associated to this secret key.
    pub fn tree(&self) -> &LdlTree {
        &self.tree
    }

    // SIGNATURE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Signs a message with the secret key.
    ///
    /// Takes a randomness generator implementing `Rng` and outputs a signature `Signature`.
    ///
    /// # Errors
    /// Returns an error of signature generation fails.
    pub fn sign<R: Rng>(&self, message: Word, rng: &mut R) -> Signature {
        let mut nonce_bytes = [0u8; SIG_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::new(nonce_bytes);

        let c = hash_to_point_rpo256(message, &nonce);
        let (s1, s2) = self.sign_helper(c, rng);

        Signature::new(nonce, s1, s2)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Derives the public key corresponding to this secret key using h = g /f [mod ϕ][mod p].
    fn compute_pub_key_poly(&self) -> PubKeyPoly {
        let g: Polynomial<FalconFelt> = self.secret_key[0].clone().into();
        let g_fft = g.fft();
        let minus_f: Polynomial<FalconFelt> = self.secret_key[1].clone().into();
        let f = -minus_f;
        let f_fft = f.fft();
        let h_fft = g_fft.hadamard_div(&f_fft);
        h_fft.ifft().into()
    }

    /// Signs a message polynomial with the secret key.
    ///
    /// Takes a randomness generator implementing `Rng` and message polynomial representing `c`
    /// the hash-to-point of the message to be signed. It outputs a tuple of signature polynomials
    /// `(s1, s2)`.
    fn sign_helper<R: Rng>(
        &self,
        c: Polynomial<FalconFelt>,
        rng: &mut R,
    ) -> (SignaturePoly, SignaturePoly) {
        let one_over_q = 1.0 / (MODULUS as f64);
        let c_over_q_fft = c.map(|cc| Complex::new(one_over_q * cc.value() as f64, 0.0)).fft();

        // B = [[FFT(g), -FFT(f)], [FFT(G), -FFT(F)]]
        let [g_fft, minus_f_fft, big_g_fft, minus_big_f_fft] = to_complex_fft(&self.secret_key);
        let t0 = c_over_q_fft.hadamard_mul(&minus_big_f_fft);
        let t1 = -c_over_q_fft.hadamard_mul(&minus_f_fft);

        loop {
            let bold_s = loop {
                let z = ffsampling(&(t0.clone(), t1.clone()), &self.tree, rng);
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

                break [-s0, s1];
            };
            let s1 = bold_s[0].ifft();
            let s2 = bold_s[1].ifft();
            let s1_coef: [i16; N] = s1
                .coefficients
                .iter()
                .map(|a| a.re.round() as i16)
                .collect::<Vec<i16>>()
                .try_into()
                .expect("The number of coefficients should be equal to N");
            let s2_coef: [i16; N] = s2
                .coefficients
                .iter()
                .map(|a| a.re.round() as i16)
                .collect::<Vec<i16>>()
                .try_into()
                .expect("The number of coefficients should be equal to N");

            if let Ok(s1) = SignaturePoly::try_from(&s1_coef) {
                if let Ok(s2) = SignaturePoly::try_from(&s2_coef) {
                    if s2.fft().coefficients.iter().all(|&c| c != FalconFelt::zero()) {
                        return (s1, s2);
                    }
                }
            }
        }
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let basis = &self.secret_key;

        // header
        let n = basis[0].coefficients.len();
        let l = n.checked_ilog2().unwrap() as u8;
        let header: u8 = (5 << 4) | l;

        let f = &basis[1];
        let g = &basis[0];
        let capital_f = &basis[3];

        let mut buffer = Vec::with_capacity(1281);
        buffer.push(header);

        let f_i8: Vec<i8> = f.coefficients.iter().map(|&a| -a as i8).collect();
        let f_i8_encoded = encode_i8(&f_i8, WIDTH_SMALL_POLY_COEFFICIENT).unwrap();
        buffer.extend_from_slice(&f_i8_encoded);

        let g_i8: Vec<i8> = g.coefficients.iter().map(|&a| a as i8).collect();
        let g_i8_encoded = encode_i8(&g_i8, WIDTH_SMALL_POLY_COEFFICIENT).unwrap();
        buffer.extend_from_slice(&g_i8_encoded);

        let big_f_i8: Vec<i8> = capital_f.coefficients.iter().map(|&a| -a as i8).collect();
        let big_f_i8_encoded = encode_i8(&big_f_i8, WIDTH_BIG_POLY_COEFFICIENT).unwrap();
        buffer.extend_from_slice(&big_f_i8_encoded);
        target.write_bytes(&buffer);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let byte_vector: [u8; SK_LEN] = source.read_array()?;

        // check length
        if byte_vector.len() < 2 {
            return  Err(DeserializationError::InvalidValue("Invalid encoding length: Failed to decode as length is different from the one expected".to_string()));
        }

        // read fields
        let header = byte_vector[0];

        // check fixed bits in header
        if (header >> 4) != 5 {
            return Err(DeserializationError::InvalidValue("Invalid header format".to_string()));
        }

        // check log n
        let logn = (header & 15) as usize;
        let n = 1 << logn;

        // match against const variant generic parameter
        if n != N {
            return Err(DeserializationError::InvalidValue(
                "Unsupported Falcon DSA variant".to_string(),
            ));
        }

        if byte_vector.len() != SK_LEN {
            return Err(DeserializationError::InvalidValue("Invalid encoding length: Failed to decode as length is different from the one expected".to_string()));
        }

        let chunk_size_f = ((n * WIDTH_SMALL_POLY_COEFFICIENT) + 7) >> 3;
        let chunk_size_g = ((n * WIDTH_SMALL_POLY_COEFFICIENT) + 7) >> 3;
        let chunk_size_big_f = ((n * WIDTH_BIG_POLY_COEFFICIENT) + 7) >> 3;

        let f = decode_i8(&byte_vector[1..chunk_size_f + 1], WIDTH_SMALL_POLY_COEFFICIENT).unwrap();
        let g = decode_i8(
            &byte_vector[chunk_size_f + 1..(chunk_size_f + chunk_size_g + 1)],
            WIDTH_SMALL_POLY_COEFFICIENT,
        )
        .unwrap();
        let big_f = decode_i8(
            &byte_vector[(chunk_size_f + chunk_size_g + 1)
                ..(chunk_size_f + chunk_size_g + chunk_size_big_f + 1)],
            WIDTH_BIG_POLY_COEFFICIENT,
        )
        .unwrap();

        let f = Polynomial::new(f.iter().map(|&c| FalconFelt::new(c.into())).collect());
        let g = Polynomial::new(g.iter().map(|&c| FalconFelt::new(c.into())).collect());
        let big_f = Polynomial::new(big_f.iter().map(|&c| FalconFelt::new(c.into())).collect());

        // big_g * f - g * big_f = p (mod X^n + 1)
        let big_g = g.fft().hadamard_div(&f.fft()).hadamard_mul(&big_f.fft()).ifft();
        let basis = [
            g.map(|f| f.balanced_value()),
            -f.map(|f| f.balanced_value()),
            big_g.map(|f| f.balanced_value()),
            -big_f.map(|f| f.balanced_value()),
        ];
        Ok(Self::from_short_lattice_basis(basis))
    }
}

// HELPER FUNCTIONS
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
