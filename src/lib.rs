#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[cfg_attr(test, macro_use)]
extern crate alloc;

pub mod hash;
pub mod merkle;

// RE-EXPORTS
// ================================================================================================

pub use winter_crypto::{RandomCoin, RandomCoinError};

pub use winter_math::{fields::f64::BaseElement as Felt, FieldElement, StarkField};

pub mod utils {
    pub use winter_utils::{
        collections, string, uninit_vector, ByteReader, ByteWriter, Deserializable,
        DeserializationError, Serializable, SliceReader,
    };
}

// TYPE ALIASES
// ================================================================================================

/// A group of four field elements in the Miden base field.
pub type Word = [Felt; WORD_SIZE];

// CONSTANTS
// ================================================================================================

/// Number of field elements in a word.
pub const WORD_SIZE: usize = 4;

/// Field element representing ZERO in the Miden base filed.
pub const ZERO: Felt = Felt::ZERO;

/// Field element representing ONE in the Miden base filed.
pub const ONE: Felt = Felt::ONE;
