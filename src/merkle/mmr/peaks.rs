use super::{
    super::{RpoDigest, Vec, ZERO},
    Felt, MmrError, MmrProof, Rpo256, Word,
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MmrPeaks {
    /// The number of leaves is used to differentiate accumulators that have the same number of
    /// peaks. This happens because the number of peaks goes up-and-down as the structure is used
    /// causing existing trees to be merged and new ones to be created. As an example, every time
    /// the [Mmr] has a power-of-two number of leaves there is a single peak.
    ///
    /// Every tree in the [Mmr] forest has a distinct power-of-two size, this means only the right
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
    num_leaves: usize,

    /// All the peaks of every tree in the [Mmr] forest. The peaks are always ordered by number of
    /// leaves, starting from the peak with most children, to the one with least.
    ///
    /// Invariant: The length of `peaks` must be equal to the number of true bits in `num_leaves`.
    peaks: Vec<RpoDigest>,
}

impl MmrPeaks {
    pub fn new(num_leaves: usize, peaks: Vec<RpoDigest>) -> Result<Self, MmrError> {
        if num_leaves.count_ones() as usize != peaks.len() {
            return Err(MmrError::InvalidPeaks);
        }

        Ok(Self { num_leaves, peaks })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a count of the [Mmr]'s leaves.
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Returns the current peaks of the [Mmr].
    pub fn peaks(&self) -> &[RpoDigest] {
        &self.peaks
    }

    /// Hashes the peaks.
    ///
    /// The procedure will:
    /// - Flatten and pad the peaks to a vector of Felts.
    /// - Hash the vector of Felts.
    pub fn hash_peaks(&self) -> Word {
        Rpo256::hash_elements(&self.flatten_and_pad_peaks()).into()
    }

    pub fn verify(&self, value: RpoDigest, opening: MmrProof) -> bool {
        let root = &self.peaks[opening.peak_index()];
        opening.merkle_path.verify(opening.relative_pos() as u64, value, root)
    }

    /// Flattens and pads the peaks to make hashing inside of the Miden VM easier.
    ///
    /// The procedure will:
    /// - Flatten the vector of Words into a vector of Felts.
    /// - Pad the peaks with ZERO to an even number of words, this removes the need to handle RPO
    ///   padding.
    /// - Pad the peaks to a minimum length of 16 words, which reduces the constant cost of
    ///   hashing.
    pub fn flatten_and_pad_peaks(&self) -> Vec<Felt> {
        let num_peaks = self.peaks.len();

        // To achieve the padding rules above we calculate the length of the final vector.
        // This is calculated as the number of field elements. Each peak is 4 field elements.
        // The length is calculated as follows:
        // - If there are less than 16 peaks, the data is padded to 16 peaks and as such requires
        //   64 field elements.
        // - If there are more than 16 peaks and the number of peaks is odd, the data is padded to
        //   an even number of peaks and as such requires `(num_peaks + 1) * 4` field elements.
        // - If there are more than 16 peaks and the number of peaks is even, the data is not padded
        //   and as such requires `num_peaks * 4` field elements.
        let len = if num_peaks < 16 {
            64
        } else if num_peaks % 2 == 1 {
            (num_peaks + 1) * 4
        } else {
            num_peaks * 4
        };

        let mut elements = Vec::with_capacity(len);
        elements.extend_from_slice(
            &self
                .peaks
                .as_slice()
                .iter()
                .map(|digest| digest.into())
                .collect::<Vec<Word>>()
                .concat(),
        );
        elements.resize(len, ZERO);
        elements
    }
}
