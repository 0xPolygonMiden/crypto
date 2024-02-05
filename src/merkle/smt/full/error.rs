use core::fmt;

use crate::{hash::rpo::RpoDigest, utils::collections::Vec, Word};

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
