use core::ops::Deref;

use super::{
    super::{LOG_N, N, PK_LEN},
    ByteReader, ByteWriter, Deserializable, DeserializationError, FalconFelt, Felt, Polynomial,
    Serializable, Signature, Word, MODULUS,
};
use crate::hash::rpo::Rpo256;
use num::Zero;

// PUBLIC KEY
// ================================================================================================

/// A public key for verifying signatures.
///
/// The public key is a [Word] (i.e., 4 field elements) that is the hash of the coefficients of
/// the polynomial representing the raw bytes of the expanded public key.
///
/// For Falcon-512, the first byte of the expanded public key is always equal to log2(512) i.e., 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(Word);

impl PublicKey {
    /// Returns a new [PublicKey] which is a commitment to the provided expanded public key.
    pub fn new(pub_key: Word) -> Self {
        Self(pub_key)
    }

    /// Verifies the provided signature against provided message and this public key.
    pub fn verify(&self, message: Word, signature: &Signature) -> bool {
        signature.verify(message, self.0)
    }
}

impl From<PubKeyPoly> for PublicKey {
    fn from(pk_poly: PubKeyPoly) -> Self {
        let pk_felts: Polynomial<Felt> = pk_poly.0.into();
        let pk_digest = Rpo256::hash_elements(&pk_felts.coefficients).into();
        Self(pk_digest)
    }
}

impl From<PublicKey> for Word {
    fn from(key: PublicKey) -> Self {
        key.0
    }
}

// PUBLIC KEY POLYNOMIAL
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubKeyPoly(Polynomial<FalconFelt>);

impl Deref for PubKeyPoly {
    type Target = Polynomial<FalconFelt>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Polynomial<FalconFelt>> for PubKeyPoly {
    fn from(pk_poly: Polynomial<FalconFelt>) -> Self {
        Self(pk_poly)
    }
}

impl Serializable for PubKeyPoly {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut buf = [0_u8; PK_LEN];
        buf[0] = 9;

        let mut acc = 0_u32;
        let mut acc_len = 0;

        let mut input_pos = 1;
        for c in self.0.coefficients.iter() {
            let c = c.value();
            acc = (acc << 14) | c as u32;
            acc_len += 14;
            while acc_len >= 8 {
                acc_len -= 8;
                buf[input_pos] = (acc >> acc_len) as u8;
                input_pos += 1;
            }
        }
        if acc_len > 0 {
            buf[input_pos] = (acc >> (8 - acc_len)) as u8;
        }

        target.write(buf);
    }
}

impl Deserializable for PubKeyPoly {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let buf = source.read_array::<PK_LEN>()?;

        if buf[0] != LOG_N as u8 {
            return Err(DeserializationError::InvalidValue(format!(
                "Failed to decode public key: expected the first byte to be {LOG_N} but was {}",
                buf[0]
            )));
        }

        let mut acc = 0_u32;
        let mut acc_len = 0;

        let mut output = [FalconFelt::zero(); N];
        let mut output_idx = 0;

        for &byte in buf.iter().skip(1) {
            acc = (acc << 8) | (byte as u32);
            acc_len += 8;

            if acc_len >= 14 {
                acc_len -= 14;
                let w = (acc >> acc_len) & 0x3FFF;
                if w >= MODULUS as u32 {
                    return Err(DeserializationError::InvalidValue(format!("Failed to decode public key: coefficient {w} is greater than or equal to the field modulus {MODULUS}")));
                }
                output[output_idx] = FalconFelt::new((w) as i16);
                output_idx += 1;
            }
        }

        if (acc & ((1u32 << acc_len) - 1)) == 0 {
            Ok(Polynomial::new(output.to_vec()).into())
        } else {
            Err(DeserializationError::InvalidValue(
                "Failed to decode public key: input not fully consumed".to_string(),
            ))
        }
    }
}
