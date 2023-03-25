//! A fully materialized Merkle mountain range (MMR).
//!
//! A MMR is a forest structure, i.e. it is an ordered set of disjoint rooted trees. The trees are
//! ordered by size, from the most to least number of leaves. Every tree is a perfect binary tree,
//! meaning a tree has all its leaves at the same depth, and every inner node has a branch-factor
//! of 2 with both children set.
//!
//! Additionally the structure only supports adding leaves to the right-most tree, the one with the
//! least number of leaves. The structure preserves the invariant that each tree has different
//! depths, i.e. as part of adding adding a new element to the forest the trees with same depth are
//! merged, creating a new tree with depth d+1, this process is continued until the property is
//! restabilished.
use super::bit::TrueBitPositionIterator;
use super::{super::Vec, MmrPeaks, MmrProof, Rpo256, Word};
use crate::merkle::MerklePath;
use core::fmt::{Display, Formatter};

#[cfg(feature = "std")]
use std::error::Error;

// MMR
// ===============================================================================================

/// A fully materialized Merkle Mountain Range, with every tree in the forest and all their
/// elements.
///
/// Since this is a full representation of the MMR, elements are never removed and the MMR will
/// grow roughly `O(2n)` in number of leaf elements.
pub struct Mmr {
    /// Refer to the `forest` method documentation for details of the semantics of this value.
    pub(super) forest: usize,

    /// Contains every element of the forest.
    ///
    /// The trees are in postorder sequential representation. This representation allows for all
    /// the elements of every tree in the forest to be stored in the same sequential buffer. It
    /// also means new elements can be added to the forest, and merging of trees is very cheap with
    /// no need to copy elements.
    pub(super) nodes: Vec<Word>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum MmrError {
    InvalidPosition(usize),
}

impl Display for MmrError {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            MmrError::InvalidPosition(pos) => write!(fmt, "Mmr does not contain position {pos}"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for MmrError {}

impl Default for Mmr {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmr {
    // CONSTRUCTORS
    // ============================================================================================

    /// Constructor for an empty `Mmr`.
    pub fn new() -> Mmr {
        Mmr {
            forest: 0,
            nodes: Vec::new(),
        }
    }

    // ACCESSORS
    // ============================================================================================

    /// Returns the MMR forest representation.
    ///
    /// The forest value has the following interpretations:
    /// - its value is the number of elements in the forest
    /// - bit count corresponds to the number of trees in the forest
    /// - each true bit position determines the depth of a tree in the forest
    pub const fn forest(&self) -> usize {
        self.forest
    }

    // FUNCTIONALITY
    // ============================================================================================

    /// Given a leaf position, returns the Merkle path to its corresponding peak. If the position
    /// is greater-or-equal than the tree size an error is returned.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    pub fn open(&self, pos: usize) -> Result<MmrProof, MmrError> {
        // find the target tree responsible for the MMR position
        let tree_bit =
            leaf_to_corresponding_tree(pos, self.forest).ok_or(MmrError::InvalidPosition(pos))?;
        let forest_target = 1usize << tree_bit;

        // isolate the trees before the target
        let forest_before = self.forest & high_bitmask(tree_bit + 1);
        let index_offset = nodes_in_forest(forest_before);

        // find the root
        let index = nodes_in_forest(forest_target) - 1;

        // update the value position from global to the target tree
        let relative_pos = pos - forest_before;

        // collect the path and the final index of the target value
        let (_, path) =
            self.collect_merkle_path_and_value(tree_bit, relative_pos, index_offset, index);

        Ok(MmrProof {
            forest: self.forest,
            position: pos,
            merkle_path: MerklePath::new(path),
        })
    }

    /// Returns the leaf value at position `pos`.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    pub fn get(&self, pos: usize) -> Result<Word, MmrError> {
        // find the target tree responsible for the MMR position
        let tree_bit =
            leaf_to_corresponding_tree(pos, self.forest).ok_or(MmrError::InvalidPosition(pos))?;
        let forest_target = 1usize << tree_bit;

        // isolate the trees before the target
        let forest_before = self.forest & high_bitmask(tree_bit + 1);
        let index_offset = nodes_in_forest(forest_before);

        // find the root
        let index = nodes_in_forest(forest_target) - 1;

        // update the value position from global to the target tree
        let relative_pos = pos - forest_before;

        // collect the path and the final index of the target value
        let (value, _) =
            self.collect_merkle_path_and_value(tree_bit, relative_pos, index_offset, index);

        Ok(value)
    }

    /// Adds a new element to the MMR.
    pub fn add(&mut self, el: Word) {
        // Note: every node is also a tree of size 1, adding an element to the forest creates a new
        // rooted-tree of size 1. This may temporarily break the invariant that every tree in the
        // forest has different sizes, the loop below will eagerly merge trees of same size and
        // restore the invariant.
        self.nodes.push(el);

        let mut left_offset = self.nodes.len().saturating_sub(2);
        let mut right = el;
        let mut left_tree = 1;
        while self.forest & left_tree != 0 {
            right = *Rpo256::merge(&[self.nodes[left_offset].into(), right.into()]);
            self.nodes.push(right);

            left_offset = left_offset.saturating_sub(nodes_in_forest(left_tree));
            left_tree <<= 1;
        }

        self.forest += 1;
    }

    /// Returns an accumulator representing the current state of the MMMR.
    pub fn accumulator(&self) -> MmrPeaks {
        let peaks: Vec<Word> = TrueBitPositionIterator::new(self.forest)
            .rev()
            .map(|bit| nodes_in_forest(1 << bit))
            .scan(0, |offset, el| {
                *offset += el;
                Some(*offset)
            })
            .map(|offset| self.nodes[offset - 1])
            .collect();

        MmrPeaks {
            num_leaves: self.forest,
            peaks,
        }
    }

    // UTILITIES
    // ============================================================================================

    /// Internal function used to collect the Merkle path of a value.
    fn collect_merkle_path_and_value(
        &self,
        tree_bit: u32,
        relative_pos: usize,
        index_offset: usize,
        mut index: usize,
    ) -> (Word, Vec<Word>) {
        // collect the Merkle path
        let mut tree_depth = tree_bit as usize;
        let mut path = Vec::with_capacity(tree_depth + 1);
        while tree_depth > 0 {
            let bit = relative_pos & tree_depth;
            let right_offset = index - 1;
            let left_offset = right_offset - nodes_in_forest(tree_depth);

            // Elements to the right have a higher position because they were
            // added later. Therefore when the bit is true the node's path is
            // to the right, and its sibling to the left.
            let sibling = if bit != 0 {
                index = right_offset;
                self.nodes[index_offset + left_offset]
            } else {
                index = left_offset;
                self.nodes[index_offset + right_offset]
            };

            tree_depth >>= 1;
            path.push(sibling);
        }

        // the rest of the codebase has the elements going from leaf to root, adjust it here for
        // easy of use/consistency sake
        path.reverse();

        let value = self.nodes[index_offset + index];
        (value, path)
    }
}

impl<T> From<T> for Mmr
where
    T: IntoIterator<Item = Word>,
{
    fn from(values: T) -> Self {
        let mut mmr = Mmr::new();
        for v in values {
            mmr.add(v)
        }
        mmr
    }
}

// UTILITIES
// ===============================================================================================

/// Given a 0-indexed leaf position and the current forest, return the tree number responsible for
/// the position.
///
/// Note:
/// The result is a tree position `p`, it has the following interpretations. $p+1$ is the depth of
/// the tree, which corresponds to the size of a Merkle proof for that tree. $2^p$ is equal to the
/// number of leaves in this particular tree. and $2^(p+1)-1$ corresponds to size of the tree.
pub(crate) const fn leaf_to_corresponding_tree(pos: usize, forest: usize) -> Option<u32> {
    if pos >= forest {
        None
    } else {
        // - each bit in the forest is a unique tree and the bit position its power-of-two size
        // - each tree owns a consecutive range of positions equal to its size from left-to-right
        // - this means the first tree owns from `0` up to the `2^k_0` first positions, where `k_0`
        // is the highest true bit position, the second tree from `2^k_0 + 1` up to `2^k_1` where
        // `k_1` is the second higest bit, so on.
        // - this means the highest bits work as a category marker, and the position is owned by
        // the first tree which doesn't share a high bit with the position
        let before = forest & pos;
        let after = forest ^ before;
        let tree = after.ilog2();

        Some(tree)
    }
}

/// Return a bitmask for the bits including and above the given position.
pub(crate) const fn high_bitmask(bit: u32) -> usize {
    if bit > usize::BITS - 1 {
        0
    } else {
        usize::MAX << bit
    }
}

/// Return the total number of nodes of a given forest
///
/// Panics:
///
/// This will panic if the forest has size greater than `usize::MAX / 2`
pub(crate) const fn nodes_in_forest(forest: usize) -> usize {
    // - the size of a perfect binary tree is $2^{k+1}-1$ or $2*2^k-1$
    // - the forest represents the sum of $2^k$ so a single multiplication is necessary
    // - the number of `-1` is the same as the number of trees, which is the same as the number
    // bits set
    let tree_count = forest.count_ones() as usize;
    forest * 2 - tree_count
}
