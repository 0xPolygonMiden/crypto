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
    /// Hashes the peaks.
    ///
    /// The hashing is optimized to work with the Miden VM, the procedure will:
    ///
    /// - Pad the peaks with ZERO to an even number of words, this removes the need to handle RPO padding.
    /// - Pad the peaks to a minimum length of 16 words, which reduces the constant cost of
    ///   hashing.
    pub fn hash_peaks(&self) -> Word {
        let mut copy = self.peaks.clone();

        if copy.len() < 16 {
            copy.resize(16, [ZERO; WORD_SIZE])
        } else if copy.len() % 2 == 1 {
            copy.push([ZERO; WORD_SIZE])
        }

        Rpo256::hash_elements(&copy.as_slice().concat()).into()
    }

    pub fn verify(&self, value: Word, opening: MmrProof) -> bool {
        let root = &self.peaks[opening.peak_index()];
        opening.merkle_path.verify(opening.relative_pos() as u64, value, root)
    }
}
