use crate::{
    hash::rpo::Rpo256,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    Felt, Word, ZERO,
};

mod error;
mod keys;
mod math;
mod signature;

use self::math::Polynomial;
pub use error::FalconError;
pub use keys::{PublicKey, SecretKey};
pub use signature::Signature;

// CONSTANTS
// ================================================================================================

// The Falcon modulus.
const MODULUS: u32 = 12289;

// The Falcon parameters for Falcon-512. This is the degree of the polynomial `phi := x^N + 1`
// defining the ring Z_p[x]/(phi).
const N: usize = 512;
const LOG_N: usize = 9;

/// Length of signature header.
const SIG_HEADER_LEN: usize = 1;

/// Length of nonce used for key-pair generation.
const SIG_NONCE_LEN: usize = 40;

/// Number of filed elements used to encode a nonce.
const NONCE_ELEMENTS: usize = 8;

/// Public key length as a u8 vector.
pub const PK_LEN: usize = 897;

/// Secret key length as a u8 vector.
pub const SK_LEN: usize = 1281;

/// Signature length as a u8 vector.
const SIG_LEN: usize = 625;

/// Bound on the squared-norm of the signature.
const SIG_L2_BOUND: u64 = 34034726;

/// Standard deviation of the Gaussian over the lattice.
const SIGMA: f64 = 165.7366171829776;

// TYPE ALIASES
// ================================================================================================

type SignatureBytes = [u8; SIG_HEADER_LEN + SIG_NONCE_LEN + SIG_LEN];
type PublicKeyBytes = [u8; PK_LEN];
type NonceBytes = [u8; SIG_NONCE_LEN];
type NonceElements = [Felt; NONCE_ELEMENTS];
type B0 = [Polynomial<i16>; 4];
