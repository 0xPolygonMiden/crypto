use core::fmt::{Display, Formatter};
#[cfg(feature = "std")]
use std::error::Error;

use crate::merkle::MerkleError;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MmrError {
    InvalidPosition(usize),
    InvalidPeaks,
    InvalidPeak,
    InvalidUpdate,
    UnknownPeak,
    MerkleError(MerkleError),
}

impl Display for MmrError {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            MmrError::InvalidPosition(pos) => write!(fmt, "Mmr does not contain position {pos}"),
            MmrError::InvalidPeaks => write!(fmt, "Invalid peaks count"),
            MmrError::InvalidPeak => {
                write!(fmt, "Peak values does not match merkle path computed root")
            }
            MmrError::InvalidUpdate => write!(fmt, "Invalid mmr update"),
            MmrError::UnknownPeak => {
                write!(fmt, "Peak not in Mmr")
            }
            MmrError::MerkleError(err) => write!(fmt, "{}", err),
        }
    }
}

#[cfg(feature = "std")]
impl Error for MmrError {}
