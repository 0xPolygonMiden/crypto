//! A partial view of the MMR, useful to maintain an update proof for a single value.
use super::{
    super::{MerklePath, Vec},
    full::nodes_in_forest,
    Rpo256, Word,
};
use core::fmt::{Display, Formatter};

#[cfg(feature = "std")]
use std::error::Error;

/// A partial view of the MMR.
///
/// Data structure used to maintain the proof of a single value up-to-date. Only the data relevant
/// to `value` is stored, meaning the path from the leaf to the peak, and the peaks in the MMR that
/// may be merged with the current peak. Required updates to the structure are very infrequent, and
/// require one value, the new entry to the right of the current peak added during a merge.
#[derive(Debug, Clone, PartialEq)]
pub struct MmrPartial {
    /// The MMR peaks of interest for this partial view, this includes all the peaks to the left of
    /// the current root, and the root itself.
    pub(crate) peaks_partial: Vec<Word>,

    /// The representation of all the peaks in this partial view.
    pub(crate) forest_partial: usize,

    /// The Merkle opening, starting from the value's sibling up to and excluding the root of the
    /// responsible tree.
    pub(crate) path: MerklePath,

    /// The value this opening corresponds to
    pub(crate) value: Word,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MmrPartialError {
    PeaksCanNotBeEmpty,
    PeaksAndForestDontmatch,
}

impl Display for MmrPartialError {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            MmrPartialError::PeaksCanNotBeEmpty => {
                write!(fmt, "Peak can not be an empty list")
            }
            MmrPartialError::PeaksAndForestDontmatch => {
                write!(
                    fmt,
                    "The number of peaks and the number of true bits in forest must be the same"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for MmrPartialError {}

impl MmrPartial {
    // CONSTRUCTORS
    // ============================================================================================

    pub fn new(
        peaks_partial: Vec<Word>,
        forest_partial: usize,
        path: MerklePath,
        value: Word,
    ) -> Result<MmrPartial, MmrPartialError> {
        if peaks_partial.is_empty() {
            Err(MmrPartialError::PeaksCanNotBeEmpty)
        } else if peaks_partial.len() as u32 != forest_partial.count_ones() {
            Err(MmrPartialError::PeaksAndForestDontmatch)
        } else {
            Ok(MmrPartial {
                peaks_partial,
                forest_partial,
                path,
                value,
            })
        }
    }

    // FUNCTIONALITY
    // ============================================================================================

    /// Given the root's right_sibling, update the partial view
    ///
    /// Note: It is the caller's responsability to call update with the correct sibling node,
    /// otherwise the updated root will be incorrect.
    pub fn update(&mut self, right_sibling: Word) {
        // NOTE: the constructor ensures the peaks_partial has enough elements so that the `unwrap`s
        // below wont panic
        let curr_root = self.peaks_partial.pop().unwrap();
        let mut new_root = *Rpo256::merge(&[curr_root.into(), right_sibling.into()]);
        self.path.push(right_sibling);

        let mut target_tree = 1 << (self.forest_partial.trailing_zeros() + 1);
        while self.forest_partial & target_tree != 0 {
            let left_node = self.peaks_partial.pop().unwrap();
            new_root = *Rpo256::merge(&[left_node.into(), new_root.into()]);
            self.path.push(left_node);
            target_tree <<= 1;
        }
        self.forest_partial += 1 << self.forest_partial.trailing_zeros();
        self.peaks_partial.push(new_root);
    }

    /// Returns the offset of `right_sibling` required to update this partial view.
    ///
    /// This is the global node offset of the corresponding MMR.
    pub fn update_offset(&self) -> usize {
        let right_forest = 1 << self.forest_partial.trailing_zeros();
        (nodes_in_forest(self.forest_partial) + nodes_in_forest(right_forest)) - 1
    }
}
