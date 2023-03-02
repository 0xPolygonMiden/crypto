/// The representation of a single Merkle path.
use super::super::MerklePath;
use super::full::{high_bitmask, leaf_to_corresponding_tree};

#[derive(Debug, Clone, PartialEq)]
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

    pub fn peak_index(&self) -> usize {
        let root = leaf_to_corresponding_tree(self.position, self.forest)
            .expect("position must be part of the forest");
        (self.forest.count_ones() - root - 1) as usize
    }
}
