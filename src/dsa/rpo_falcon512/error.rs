use core::fmt;

use super::{LOG_N, MODULUS, PK_LEN};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FalconError {
    KeyGenerationFailed,
    PubKeyDecodingExtraData,
    PubKeyDecodingInvalidCoefficient(u32),
    PubKeyDecodingInvalidLength(usize),
    PubKeyDecodingInvalidTag(u8),
    SigDecodingTooBigHighBits(u32),
    SigDecodingInvalidRemainder,
    SigDecodingNonZeroUnusedBitsLastByte,
    SigDecodingMinusZero,
    SigDecodingIncorrectEncodingAlgorithm,
    SigDecodingNotSupportedDegree(u8),
    BadEncodingLength,
    InvalidHeaderFormat,
    WrongVariant,
}

impl fmt::Display for FalconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FalconError::*;
        match self {
            KeyGenerationFailed => write!(f, "Failed to generate a private-public key pair"),
            PubKeyDecodingExtraData => {
                write!(f, "Failed to decode public key: input not fully consumed")
            }
            PubKeyDecodingInvalidCoefficient(val) => {
                write!(f, "Failed to decode public key: coefficient {val} is greater than or equal to the field modulus {MODULUS}")
            }
            PubKeyDecodingInvalidLength(len) => {
                write!(f, "Failed to decode public key: expected {PK_LEN} bytes but received {len}")
            }
            PubKeyDecodingInvalidTag(byte) => {
                write!(f, "Failed to decode public key: expected the first byte to be {LOG_N} but was {byte}")
            }
            SigDecodingTooBigHighBits(m) => {
                write!(f, "Failed to decode signature: high bits {m} exceed 2048")
            }
            SigDecodingInvalidRemainder => {
                write!(f, "Failed to decode signature: incorrect remaining data")
            }
            SigDecodingNonZeroUnusedBitsLastByte => {
                write!(f, "Failed to decode signature: Non-zero unused bits in the last byte")
            }
            SigDecodingMinusZero => write!(f, "Failed to decode signature: -0 is forbidden"),
            SigDecodingIncorrectEncodingAlgorithm => write!(f, "Failed to decode signature: not supported encoding algorithm"),
            SigDecodingNotSupportedDegree(log_n) => write!(f, "Failed to decode signature: only supported irreducible polynomial degree is 512, 2^{log_n} was provided"),
            BadEncodingLength => write!(f, "Failed to decode: length is different from the one expected"),
            InvalidHeaderFormat => write!(f, "Invalid header format"),
            WrongVariant => write!(f, "Wrong Falcon DSA variant"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FalconError {}
