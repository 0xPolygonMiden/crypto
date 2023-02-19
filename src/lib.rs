#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[cfg_attr(test, macro_use)]
extern crate alloc;

pub mod hash;
pub mod merkle;

mod word;
pub use word::{CanonicalWord, Word, WORD_SIZE};

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

// CONSTANTS
// ================================================================================================

/// Field element representing ZERO in the Miden base filed.
pub const ZERO: Felt = Felt::ZERO;

/// Field element representing ONE in the Miden base filed.
pub const ONE: Felt = Felt::ONE;

// TESTS
// ================================================================================================

#[test]
#[should_panic]
fn debug_assert_is_checked() {
    // enforce the release checks to always have `RUSTFLAGS="-C debug-assertions".
    //
    // some upstream tests are performed with `debug_assert`, and we want to assert its correctness
    // downstream.
    //
    // for reference, check
    // https://github.com/0xPolygonMiden/miden-vm/issues/433
    debug_assert!(false);
}

#[test]
#[should_panic]
#[allow(arithmetic_overflow)]
fn overflow_panics_for_test() {
    // overflows might be disabled if tests are performed in release mode. these are critical,
    // mandatory checks as overflows might be attack vectors.
    //
    // to enable overflow checks in release mode, ensure `RUSTFLAGS="-C overflow-checks"`
    let a = 1_u64;
    let b = 64;
    assert_ne!(a << b, 0);
}
