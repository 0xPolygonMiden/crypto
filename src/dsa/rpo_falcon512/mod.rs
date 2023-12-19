use crate::{
    hash::rpo::Rpo256,
    utils::{
        collections::Vec, ByteReader, ByteWriter, Deserializable, DeserializationError,
        Serializable,
    },
    Felt, StarkField, Word, ZERO,
};

#[cfg(feature = "std")]
mod ffi;

mod error;
mod keys;
mod polynomial;
mod signature;

pub use error::FalconError;
pub use keys::{sk_to_pk_bytes, KeyPair, PublicKey};
pub use polynomial::Polynomial;
pub use signature::Signature;

// CONSTANTS
// ================================================================================================

// The Falcon modulus.
const MODULUS: u16 = 12289;
const MODULUS_MINUS_1_OVER_TWO: u16 = 6144;

// The Falcon parameters for Falcon-512. This is the degree of the polynomial `phi := x^N + 1`
// defining the ring Z_p[x]/(phi).
const N: usize = 512;
const LOG_N: usize = 9;

/// Length of nonce used for key-pair generation.
const NONCE_LEN: usize = 40;

/// Number of filed elements used to encode a nonce.
const NONCE_ELEMENTS: usize = 8;

/// Public key length as a u8 vector.
const PK_LEN: usize = 897;

/// Secret key length as a u8 vector.
const SK_LEN: usize = 1281;

/// Signature length as a u8 vector.
const SIG_LEN: usize = 626;

/// Bound on the squared-norm of the signature.
const SIG_L2_BOUND: u64 = 34034726;

// TYPE ALIASES
// ================================================================================================

type SignatureBytes = [u8; NONCE_LEN + SIG_LEN];
type PublicKeyBytes = [u8; PK_LEN];
type SecretKeyBytes = [u8; SK_LEN];
type NonceBytes = [u8; NONCE_LEN];
type NonceElements = [Felt; NONCE_ELEMENTS];
