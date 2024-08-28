use alloc::vec::Vec;
use core::fmt;

use crate::{
    hash::rpo::RpoDigest,
    merkle::{LeafIndex, SMT_DEPTH},
    Word,
};

// SMT LEAF ERROR
// =================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmtLeafError {
    InconsistentKeys {
        entries: Vec<(RpoDigest, Word)>,
        key_1: RpoDigest,
        key_2: RpoDigest,
    },
    InvalidNumEntriesForMultiple(usize),
    SingleKeyInconsistentWithLeafIndex {
        key: RpoDigest,
        leaf_index: LeafIndex<SMT_DEPTH>,
    },
    MultipleKeysInconsistentWithLeafIndex {
        leaf_index_from_keys: LeafIndex<SMT_DEPTH>,
        leaf_index_supplied: LeafIndex<SMT_DEPTH>,
    },
}

#[cfg(feature = "std")]
impl std::error::Error for SmtLeafError {}

impl fmt::Display for SmtLeafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SmtLeafError::*;
        match self {
            InvalidNumEntriesForMultiple(num_entries) => {
                write!(f, "Multiple leaf requires 2 or more entries. Got: {num_entries}")
            },
            InconsistentKeys { entries, key_1, key_2 } => {
                write!(f, "Multiple leaf requires all keys to map to the same leaf index. Offending keys: {key_1} and {key_2}. Entries: {entries:?}.")
            },
            SingleKeyInconsistentWithLeafIndex { key, leaf_index } => {
                write!(
                    f,
                    "Single key in leaf inconsistent with leaf index. Key: {key}, leaf index: {}",
                    leaf_index.value()
                )
            },
            MultipleKeysInconsistentWithLeafIndex {
                leaf_index_from_keys,
                leaf_index_supplied,
            } => {
                write!(
                    f,
                    "Keys in entries map to leaf index {}, but leaf index {} was supplied",
                    leaf_index_from_keys.value(),
                    leaf_index_supplied.value()
                )
            },
        }
    }
}

// SMT PROOF ERROR
// =================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmtProofError {
    InvalidPathLength(usize),
}

#[cfg(feature = "std")]
impl std::error::Error for SmtProofError {}

impl fmt::Display for SmtProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SmtProofError::*;
        match self {
            InvalidPathLength(path_length) => {
                write!(f, "Invalid Merkle path length. Expected {SMT_DEPTH}, got {path_length}")
            },
        }
    }
}
