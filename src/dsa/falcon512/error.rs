use super::{LOG_N, MODULUS, PK_LEN};
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FalconError {
    KeyGenerationFailed,
    PubKeyDecodingExtraData,
    PubKeyDecodingInvalidCoefficient(u32),
    PubKeyDecodingInvalidLength(usize),
    PubKeyDecodingInvalidTag(u8),
    InvalidEncodingLength,
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
            InvalidEncodingLength => {
                write!(f, "Failed to decode: length is different from the one expected")
            }
            InvalidHeaderFormat => write!(f, "Invalid header format"),
            WrongVariant => write!(f, "Wrong Falcon DSA variant"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FalconError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FalconSerializationError {
    TooBigHighBits(u32),
    MinusZero,
    NonZeroUnusedBitsLastByte,
}

impl fmt::Display for FalconSerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FalconSerializationError::*;
        match self {
            TooBigHighBits(m) => {
                write!(f, "Failed to decode signature: high bits {m} exceed 2048")
            }
            NonZeroUnusedBitsLastByte => {
                write!(f, "Failed to decode signature: Non-zero unused bits in the last byte")
            }
            MinusZero => write!(f, "Failed to decode signature: -0 is forbidden"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FalconSerializationError {}
