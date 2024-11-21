use core::fmt::{Display, Formatter};
#[cfg(feature = "std")]
use std::error::Error;

use crate::merkle::MerkleError;

#[derive(Debug)]
pub enum MmrError {
    InvalidPosition(usize),
    InvalidPeaks,
    InvalidPeak,
    PeakOutOfBounds(usize, usize),
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
            },
            MmrError::PeakOutOfBounds(peak_idx, peaks_len) => write!(
                fmt,
                "Requested peak index is {} but the number of peaks is {}",
                peak_idx, peaks_len
            ),
            MmrError::InvalidUpdate => write!(fmt, "Invalid Mmr update"),
            MmrError::UnknownPeak => {
                write!(fmt, "Peak not in Mmr")
            },
            MmrError::MerkleError(err) => write!(fmt, "{}", err),
        }
    }
}

#[cfg(feature = "std")]
impl Error for MmrError {}
