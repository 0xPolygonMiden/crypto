use core::fmt::Display;

use super::SMT_DEPTH;

pub enum SmtProofError {
    InvalidPathLength(usize),
}

impl Display for SmtProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SmtProofError::InvalidPathLength(length) => {
                write!(f, "Expected path to be length {SMT_DEPTH}, but was {length}")
            }
        }
    }
}
