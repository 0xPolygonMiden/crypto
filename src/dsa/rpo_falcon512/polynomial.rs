use super::{FalconError, Felt, Vec, LOG_N, MODULUS, MODULUS_MINUS_1_OVER_TWO, N, PK_LEN};
use core::ops::{Add, Mul, Sub};

// FALCON POLYNOMIAL
// ================================================================================================

/// A polynomial over Z_p\[x\]/(phi) where phi := x^512 + 1
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Polynomial([u16; N]);

impl Polynomial {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a new polynomial from a list of coefficients.
    ///
    /// # Safety
    /// This constructor validates that the coefficients are in the valid range only in debug mode.
    pub unsafe fn new(data: [u16; N]) -> Self {
        for value in data {
            debug_assert!(value < MODULUS);
        }

        Self(data)
    }

    /// Decodes raw bytes representing a public key into a polynomial in Z_p\[x\]/(phi).
    ///
    /// # Errors
    /// Returns an error if:
    /// - The provided input is not exactly 897 bytes long.
    /// - The first byte of the input is not equal to log2(512) i.e., 9.
    /// - Any of the coefficients encoded in the provided input is greater than or equal to the
    ///   Falcon field modulus.
    pub fn from_pub_key(input: &[u8]) -> Result<Self, FalconError> {
        if input.len() != PK_LEN {
            return Err(FalconError::PubKeyDecodingInvalidLength(input.len()));
        }

        if input[0] != LOG_N as u8 {
            return Err(FalconError::PubKeyDecodingInvalidTag(input[0]));
        }

        let mut acc = 0_u32;
        let mut acc_len = 0;

        let mut output = [0_u16; N];
        let mut output_idx = 0;

        for &byte in input.iter().skip(1) {
            acc = (acc << 8) | (byte as u32);
            acc_len += 8;

            if acc_len >= 14 {
                acc_len -= 14;
                let w = (acc >> acc_len) & 0x3FFF;
                if w >= MODULUS as u32 {
                    return Err(FalconError::PubKeyDecodingInvalidCoefficient(w));
                }
                output[output_idx] = w as u16;
                output_idx += 1;
            }
        }

        if (acc & ((1u32 << acc_len) - 1)) == 0 {
            Ok(Self(output))
        } else {
            Err(FalconError::PubKeyDecodingExtraData)
        }
    }

    /// Decodes the signature into the coefficients of a polynomial in Z_p\[x\]/(phi). It assumes
    /// that the signature has been encoded using the uncompressed format.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The signature has been encoded using a different algorithm than the reference compressed
    ///   encoding algorithm.
    /// - The encoded signature polynomial is in Z_p\[x\]/(phi') where phi' = x^N' + 1 and N' != 512.
    /// - While decoding the high bits of a coefficient, the current accumulated value of its
    ///  high bits is larger than 2048.
    /// - The decoded  coefficient is -0.
    /// - The remaining unused bits in the last byte of `input` are non-zero.
    pub fn from_signature(input: &[u8]) -> Result<Self, FalconError> {
        let (encoding, log_n) = (input[0] >> 4, input[0] & 0b00001111);

        if encoding != 0b0011 {
            return Err(FalconError::SigDecodingIncorrectEncodingAlgorithm);
        }
        if log_n != 0b1001 {
            return Err(FalconError::SigDecodingNotSupportedDegree(log_n));
        }

        let input = &input[41..];
        let mut input_idx = 0;
        let mut acc = 0u32;
        let mut acc_len = 0;
        let mut output = [0_u16; N];

        for e in output.iter_mut() {
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
                    return Err(FalconError::SigDecodingTooBigHighBits(m));
                }
            }
            if s != 0 && m == 0 {
                return Err(FalconError::SigDecodingMinusZero);
            }

            *e = if s != 0 { (MODULUS as u32 - m) as u16 } else { m as u16 };
        }

        if (acc & ((1 << acc_len) - 1)) != 0 {
            return Err(FalconError::SigDecodingNonZeroUnusedBitsLastByte);
        }

        Ok(Self(output))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the coefficients of this polynomial as integers.
    pub fn inner(&self) -> [u16; N] {
        self.0
    }

    /// Returns the coefficients of this polynomial as field elements.
    pub fn to_elements(&self) -> Vec<Felt> {
        self.0.iter().map(|&a| Felt::from(a)).collect()
    }

    // POLYNOMIAL OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Multiplies two polynomials over Z_p\[x\] without reducing modulo p. Given that the degrees
    /// of the input polynomials are less than 512 and their coefficients are less than the modulus
    /// q equal to 12289, the resulting product polynomial is guaranteed to have coefficients less
    /// than the Miden prime.
    ///
    /// Note that this multiplication is not over Z_p\[x\]/(phi).
    pub fn mul_modulo_p(a: &Self, b: &Self) -> [u64; 1024] {
        let mut c = [0; 2 * N];
        for i in 0..N {
            for j in 0..N {
                c[i + j] += a.0[i] as u64 * b.0[j] as u64;
            }
        }

        c
    }

    /// Reduces a polynomial, that is the product of two polynomials over Z_p\[x\], modulo
    /// the irreducible polynomial phi. This results in an element in Z_p\[x\]/(phi).
    pub fn reduce_negacyclic(a: &[u64; 1024]) -> Self {
        let mut c = [0; N];
        for i in 0..N {
            let ai = a[N + i] % MODULUS as u64;
            let neg_ai = (MODULUS - ai as u16) % MODULUS;

            let bi = (a[i] % MODULUS as u64) as u16;
            c[i] = (neg_ai + bi) % MODULUS;
        }

        Self(c)
    }

    /// Computes the norm squared of a polynomial in Z_p\[x\]/(phi) after normalizing its
    /// coefficients to be in the interval (-p/2, p/2].
    pub fn sq_norm(&self) -> u64 {
        let mut res = 0;
        for e in self.0 {
            if e > MODULUS_MINUS_1_OVER_TWO {
                res += (MODULUS - e) as u64 * (MODULUS - e) as u64
            } else {
                res += e as u64 * e as u64
            }
        }
        res
    }
}

// Returns a polynomial representing the zero polynomial i.e. default element.
impl Default for Polynomial {
    fn default() -> Self {
        Self([0_u16; N])
    }
}

/// Multiplication over Z_p\[x\]/(phi)
impl Mul for Polynomial {
    type Output = Self;

    fn mul(self, other: Self) -> <Self as Mul<Self>>::Output {
        let mut result = [0_u16; N];
        for j in 0..N {
            for k in 0..N {
                let i = (j + k) % N;
                let a = self.0[j] as usize;
                let b = other.0[k] as usize;
                let q = MODULUS as usize;
                let mut prod = a * b % q;
                if (N - 1) < (j + k) {
                    prod = (q - prod) % q;
                }
                result[i] = ((result[i] as usize + prod) % q) as u16;
            }
        }

        Polynomial(result)
    }
}

/// Addition over Z_p\[x\]/(phi)
impl Add for Polynomial {
    type Output = Self;

    fn add(self, other: Self) -> <Self as Add<Self>>::Output {
        let mut res = self;
        res.0.iter_mut().zip(other.0.iter()).for_each(|(x, y)| *x = (*x + *y) % MODULUS);

        res
    }
}

/// Subtraction over Z_p\[x\]/(phi)
impl Sub for Polynomial {
    type Output = Self;

    fn sub(self, other: Self) -> <Self as Add<Self>>::Output {
        let mut res = self;
        res.0
            .iter_mut()
            .zip(other.0.iter())
            .for_each(|(x, y)| *x = (*x + MODULUS - *y) % MODULUS);

        res
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{Polynomial, N};

    #[test]
    fn test_negacyclic_reduction() {
        let coef1: [u16; N] = rand_utils::rand_array();
        let coef2: [u16; N] = rand_utils::rand_array();

        let poly1 = Polynomial(coef1);
        let poly2 = Polynomial(coef2);

        assert_eq!(
            poly1 * poly2,
            Polynomial::reduce_negacyclic(&Polynomial::mul_modulo_p(&poly1, &poly2))
        );
    }
}
