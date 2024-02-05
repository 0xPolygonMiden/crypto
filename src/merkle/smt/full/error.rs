use core::fmt;

use crate::{hash::rpo::RpoDigest, merkle::SMT_DEPTH, utils::collections::Vec, Word};

// SMT LEAF ERROR
// =================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmtLeafError {
    InconsistentKeysInEntries {
        entries: Vec<(RpoDigest, Word)>,
        key_1: RpoDigest,
        key_2: RpoDigest,
    },
    InvalidNumEntriesForMultiple(usize),
}

#[cfg(feature = "std")]
impl std::error::Error for SmtLeafError {}

impl fmt::Display for SmtLeafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SmtLeafError::*;
        match self {
            InvalidNumEntriesForMultiple(num_entries) => {
                write!(f, "Multiple leaf requires 2 or more entries. Got: {num_entries}")
            }
            InconsistentKeysInEntries { entries, key_1, key_2 } => {
                write!(f, "Multiple leaf requires all keys to map to the same leaf index. Offending keys: {key_1} and {key_2}. Entries: {entries:?}.")
            }
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
            }
        }
    }
}
