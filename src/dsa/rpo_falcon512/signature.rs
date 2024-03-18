use alloc::{string::ToString, vec::Vec};
use core::ops::Deref;

use super::{
    error::FalconSerializationError,
    hash_to_point::hash_to_point_rpo256,
    math::{FalconFelt, FastFft, Polynomial},
    ByteReader, ByteWriter, Deserializable, DeserializationError, Felt, Nonce, Rpo256,
    Serializable, Word, LOG_N, MODULUS, N, SIG_L2_BOUND, SIG_LEN,
};
use num::Zero;

// FALCON SIGNATURE
// ================================================================================================

/// An RPO Falcon512 signature over a message.
///
/// The signature is a pair of polynomials (s1, s2) in (Z_p\[x\]/(phi))^2 and a nonce `r`,
/// where:
/// - p := 12289
/// - phi := x^512 + 1
///
/// The signature  verifies if and only if:
/// 1. h = s2^(-1) * (c - s1)
/// 2. |s1|^2 + |s2|^2 <= SIG_L2_BOUND
///
/// where |.| is the norm and:
/// - pk = Rpo256::hash(h)
/// - c = HashToPoint(r || message)
///
/// Here h is a polynomial representing the public key and pk is its digest. c is a polynomial that
/// is the hash-to-point of the message being signed.
///
/// The signature is serialized as:
/// 1. A header byte specifying the algorithm used to encode the coefficients of the `s2` polynomial
///    together with the degree of the irreducible polynomial phi.
///    The general format of this byte is 0b0cc1nnnn where:
///     a. cc is either 01 when the compressed encoding algorithm is used and 10 when the
///     uncompressed algorithm is used.
///     b. nnnn is log2(N) where N is the degree of the irreducible polynomial phi.
///    The current implementation works always with cc equal to 0b01 and nnnn equal to 0b1001 and
///    thus the header byte is always equal to 0b00111001.
/// 2. 40 bytes for the nonce.
/// 3. 625 bytes encoding the `s1` polynomial above.
/// 4. 625 bytes encoding the `s2` polynomial above.
///
/// The total size of the signature (including the extended public key) is 1564 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    header: SignatureHeader,
    nonce: Nonce,
    s1: SignaturePoly,
    s2: SignaturePoly,
}

impl Signature {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    pub fn new(nonce: Nonce, s1: SignaturePoly, s2: SignaturePoly) -> Signature {
        Self {
            header: SignatureHeader::default(),
            nonce,
            s1,
            s2,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    // Returns the polynomial representation of the signature in Z_p[x]/(phi).
    pub fn sig_poly(&self) -> (&Polynomial<FalconFelt>, &Polynomial<FalconFelt>) {
        (&self.s1, &self.s2)
    }

    /// Returns the nonce component of the signature.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    // SIGNATURE VERIFICATION
    // --------------------------------------------------------------------------------------------

    /// Returns true if this signature is a valid signature for the specified message generated
    /// against the secret key matching the specified public key commitment.
    pub fn verify(&self, message: Word, pubkey_com: Word) -> bool {
        let c = hash_to_point_rpo256(message, &self.nonce);
        let s1 = self.s1.clone();
        let s2 = self.s2.clone();
        verify_helper(c, s1, s2, pubkey_com)
    }
}

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.header);
        target.write(&self.nonce);
        target.write(&self.s1);
        target.write(&self.s2);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = source.read()?;
        let nonce = source.read()?;
        let s1 = source.read()?;
        let s2 = source.read()?;

        Ok(Self { header, nonce, s1, s2 })
    }
}

// SIGNATURE HEADER
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeader(u8);

impl Default for SignatureHeader {
    /// TODO: add docs
    fn default() -> Self {
        Self(0b0011_0000 + LOG_N as u8)
    }
}

impl Serializable for &SignatureHeader {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.0)
    }
}

impl Deserializable for SignatureHeader {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = source.read_u8()?;
        let (encoding, log_n) = (header >> 4, header & 0b00001111);
        if encoding != 0b0011 {
            return Err(DeserializationError::InvalidValue(
                "Failed to decode signature: not supported encoding algorithm".to_string(),
            ));
        }

        if log_n as usize != LOG_N {
            return Err(DeserializationError::InvalidValue(
                format!("Failed to decode signature: only supported irreducible polynomial degree is 512, 2^{log_n} was provided")
            ));
        }

        Ok(Self(header))
    }
}

// SIGNATURE POLY
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePoly(pub Polynomial<FalconFelt>);

impl Deref for SignaturePoly {
    type Target = Polynomial<FalconFelt>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Polynomial<FalconFelt>> for SignaturePoly {
    fn from(pk_poly: Polynomial<FalconFelt>) -> Self {
        Self(pk_poly)
    }
}

impl TryFrom<&[i16; N]> for SignaturePoly {
    type Error = ();

    fn try_from(coefficients: &[i16; N]) -> Result<Self, Self::Error> {
        if are_coefficients_valid(coefficients) {
            Ok(Self(coefficients.to_vec().into()))
        } else {
            Err(())
        }
    }
}

impl Serializable for &SignaturePoly {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let sig_coeff: Vec<i16> = self.0.coefficients.iter().map(|a| a.balanced_value()).collect();
        let sk_bytes = compress_signature(&sig_coeff);
        target.write_bytes(&sk_bytes);
    }
}

impl Deserializable for SignaturePoly {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes = source.read_array::<SIG_LEN>()?;
        decompress_signature(&bytes)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
            .map(SignaturePoly::from)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Takes the hash-to-point polynomial `c` of a message and the signature polynomials over
/// the message `(s1, s2)` and returns `true` is the signature is a valid signature for
/// the given parameters, otherwise it returns `false`.
fn verify_helper(
    c: Polynomial<FalconFelt>,
    s1: SignaturePoly,
    s2: SignaturePoly,
    pubkey_com: Word,
) -> bool {
    let s1_fft = s1.fft();
    let s2_fft = s2.fft();
    let c_fft = c.fft();

    // h = s2^(-1) * (c - s1)
    let h_fft = (c_fft - s1_fft).hadamard_div(&s2_fft);
    let h = h_fft.ifft();

    let length_squared_s1 = s1.norm_squared();
    let length_squared_s2 = s2.norm_squared();
    let length_squared = length_squared_s1 + length_squared_s2;
    let is_short = length_squared < SIG_L2_BOUND;

    let h: Polynomial<Felt> = h.into();
    let h_digest: Word = Rpo256::hash_elements(&h.coefficients).into();

    h_digest == pubkey_com && is_short
}

/// Checks whether a set of coefficients is a valid one for a signature polynomial.
fn are_coefficients_valid(x: &[i16]) -> bool {
    if x.len() != N {
        return false;
    }

    for &c in x {
        if !(-2047..=2047).contains(&c) {
            return false;
        }
    }

    true
}

/// Takes as input a list of integers x and returns a bytestring that encodes/compress' it.
/// If this is not possible, it returns False.
///
/// For each coefficient of x:
/// - the sign is encoded on 1 bit
/// - the 7 lower bits are encoded naively (binary)
/// - the high bits are encoded in unary encoding
///
/// This method can fail, in which case it returns None.
///
/// Algorithm 17 p. 47 of the specification [1].
///
/// [1]: https://falcon-sign.info/falcon.pdf
fn compress_signature(x: &[i16]) -> Vec<u8> {
    let mut buf = vec![0_u8; SIG_LEN];

    let mut acc = 0;
    let mut acc_len = 0;
    let mut v = 0;
    let mut t;
    let mut w;

    for &c in x {
        acc <<= 1;
        t = c;

        if t < 0 {
            t = -t;
            acc |= 1;
        }
        w = t as u16;

        acc <<= 7;
        let mask = 127_u32;
        acc |= (w as u32) & mask;
        w >>= 7;

        acc_len += 8;

        acc <<= w + 1;
        acc |= 1;
        acc_len += w + 1;

        while acc_len >= 8 {
            acc_len -= 8;

            buf[v] = (acc >> acc_len) as u8;
            v += 1;
        }
    }

    if acc_len > 0 {
        buf[v] = (acc << (8 - acc_len)) as u8;
    }

    buf
}

/// Takes as input an encoding `input` and returns a list of integers x of length N such that
/// `inputs` encodes x. If such a list does not exist, the encoding is invalid and we output
/// an error.
///
/// Algorithm 18 p. 48 of the specification [1].
///
/// [1]: https://falcon-sign.info/falcon.pdf
fn decompress_signature(input: &[u8]) -> Result<Polynomial<FalconFelt>, FalconSerializationError> {
    let mut input_idx = 0;
    let mut acc = 0u32;
    let mut acc_len = 0;
    let mut coefficients = [FalconFelt::zero(); N];

    for c in coefficients.iter_mut() {
        acc = (acc << 8) | (input[input_idx] as u32);
        input_idx += 1;
        let b = acc >> acc_len;
        let s = b & 128;
        let mut m = b & 127;

        loop {
            if acc_len == 0 {
                acc = (acc << 8) | (input[input_idx] as u32);
                input_idx += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            if m >= 2048 {
                return Err(FalconSerializationError::TooBigHighBits(m));
            }
        }
        if s != 0 && m == 0 {
            return Err(FalconSerializationError::MinusZero);
        }

        let felt = if s != 0 { (MODULUS as u32 - m) as u16 } else { m as u16 };
        *c = FalconFelt::new(felt as i16);
    }

    if (acc & ((1 << acc_len) - 1)) != 0 {
        return Err(FalconSerializationError::NonZeroUnusedBitsLastByte);
    }
    Ok(Polynomial::new(coefficients.to_vec()))
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
        let signature = key.sign(Word::default(), &mut rng).unwrap();
        let serialized = signature.to_bytes();
        let deserialized = Signature::read_from_bytes(&serialized).unwrap();
        assert_eq!(signature.sig_poly(), deserialized.sig_poly());
    }
}
