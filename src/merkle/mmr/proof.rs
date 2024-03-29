/// The representation of a single Merkle path.
use super::super::MerklePath;
use super::{full::high_bitmask, leaf_to_corresponding_tree};

// MMR PROOF
// ================================================================================================

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MmrProof {
    /// The state of the MMR when the MmrProof was created.
    pub forest: usize,

    /// The position of the leaf value on this MmrProof.
    pub position: usize,

    /// The Merkle opening, starting from the value's sibling up to and excluding the root of the
    /// responsible tree.
    pub merkle_path: MerklePath,
}

impl MmrProof {
    /// Converts the leaf global position into a local position that can be used to verify the
    /// merkle_path.
    pub fn relative_pos(&self) -> usize {
        let tree_bit = leaf_to_corresponding_tree(self.position, self.forest)
            .expect("position must be part of the forest");
        let forest_before = self.forest & high_bitmask(tree_bit + 1);
        self.position - forest_before
    }

    /// Returns index of the MMR peak against which the Merkle path in this proof can be verified.
    pub fn peak_index(&self) -> usize {
        let root = leaf_to_corresponding_tree(self.position, self.forest)
            .expect("position must be part of the forest");
        let smaller_peak_mask = 2_usize.pow(root) as usize - 1;
        let num_smaller_peaks = (self.forest & smaller_peak_mask).count_ones();
        (self.forest.count_ones() - num_smaller_peaks - 1) as usize
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{MerklePath, MmrProof};

    #[test]
    fn test_peak_index() {
        // --- single peak forest ---------------------------------------------
        let forest = 11;

        // the first 4 leaves belong to peak 0
        for position in 0..8 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 0);
        }

        // --- forest with non-consecutive peaks ------------------------------
        let forest = 11;

        // the first 8 leaves belong to peak 0
        for position in 0..8 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 0);
        }

        // the next 2 leaves belong to peak 1
        for position in 8..10 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 1);
        }

        // the last leaf is the peak 2
        let proof = make_dummy_proof(forest, 10);
        assert_eq!(proof.peak_index(), 2);

        // --- forest with consecutive peaks ----------------------------------
        let forest = 7;

        // the first 4 leaves belong to peak 0
        for position in 0..4 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 0);
        }

        // the next 2 leaves belong to peak 1
        for position in 4..6 {
            let proof = make_dummy_proof(forest, position);
            assert_eq!(proof.peak_index(), 1);
        }

        // the last leaf is the peak 2
        let proof = make_dummy_proof(forest, 6);
        assert_eq!(proof.peak_index(), 2);
    }

    fn make_dummy_proof(forest: usize, position: usize) -> MmrProof {
        MmrProof {
            forest,
            position,
            merkle_path: MerklePath::default(),
        }
    }
}
