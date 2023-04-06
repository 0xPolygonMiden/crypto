use super::{
    super::Vec,
    super::{WORD_SIZE, ZERO},
    MmrProof, Rpo256, Word,
};

#[derive(Debug, Clone, PartialEq)]
pub struct MmrPeaks {
    /// The number of leaves is used to differentiate accumulators that have the same number of
    /// peaks. This happens because the number of peaks goes up-and-down as the structure is used
    /// causing existing trees to be merged and new ones to be created. As an example, every time
    /// the MMR has a power-of-two number of leaves there is a single peak.
    ///
    /// Every tree in the MMR forest has a distinct power-of-two size, this means only the right
    /// most tree can have an odd number of elements (e.g. `1`). Additionally this means that the bits in
    /// `num_leaves` conveniently encode the size of each individual tree.
    ///
    /// Examples:
    ///
    ///    - With 5 leaves, the binary `0b101`. The number of set bits is equal the number
    ///      of peaks, in this case there are 2 peaks. The 0-indexed least-significant position of
    ///      the bit determines the number of elements of a tree, so the rightmost tree has `2**0`
    ///      elements and the left most has `2**2`.
    ///    - With 12 leaves, the binary is `0b1100`, this case also has 2 peaks, the
    ///      leftmost tree has `2**3=8` elements, and the right most has `2**2=4` elements.
    pub num_leaves: usize,

    /// All the peaks of every tree in the MMR forest. The peaks are always ordered by number of
    /// leaves, starting from the peak with most children, to the one with least.
    ///
    /// Invariant: The length of `peaks` must be equal to the number of true bits in `num_leaves`.
    pub peaks: Vec<Word>,
}

impl MmrPeaks {
    /// Hashes the peaks sequentially, compacting it to a single digest
    pub fn hash_peaks(&self) -> Word {
        Rpo256::hash_elements(&self.peaks.as_slice().concat()).into()
    }

    /// Hashes the peaks sequentially, compacting it to a single digest padded to 32 words.
    ///
    /// # Notes
    ///
    /// This version of the hash can represent up to 32 peaks. This does not mean that only the
    /// first 32 peaks are representable, but instead it causes discontinuities on representable
    /// peaks. It is possible to represent up to `sum(2^i for i in 1..3)` or `8589934590` without
    /// reaching the first discontinuity.
    pub fn hash_peaks_32(&self) -> Option<Word> {
        if self.peaks.len() > 32 {
            None
        } else {
            let mut copy = self.peaks.clone();
            copy.resize(32, [ZERO; WORD_SIZE]);
            Some(Rpo256::hash_elements(&copy.as_slice().concat()).into())
        }
    }

    pub fn verify(&self, value: Word, opening: MmrProof) -> bool {
        let root = &self.peaks[opening.peak_index()];
        opening
            .merkle_path
            .verify(opening.relative_pos() as u64, value, root)
    }
}
