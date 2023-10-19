//! Index for nodes of a binary tree based on an in-order tree walk.
//!
//! In-order walks have the parent node index split its left and right subtrees. All the left
//! children have indexes lower than the parent, meanwhile all the right subtree higher indexes.
//! This property makes it is easy to compute changes to the index by adding or subtracting the
//! leaves count.
use core::num::NonZeroUsize;

/// Index of nodes in a perfectly balanced binary tree based on an in-order tree walk.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InOrderIndex {
    idx: usize,
}

impl InOrderIndex {
    /// Constructor for a new [InOrderIndex].
    pub fn new(idx: NonZeroUsize) -> InOrderIndex {
        InOrderIndex { idx: idx.get() }
    }

    /// Constructs an index from a leaf position.
    ///
    /// Panics:
    ///
    /// If `leaf` is higher than or equal to `usize::MAX / 2`.
    pub fn from_leaf_pos(leaf: usize) -> InOrderIndex {
        // Convert the position from 0-indexed to 1-indexed, since the bit manipulation in this
        // implementation only works 1-indexed counting.
        let pos = leaf + 1;
        InOrderIndex { idx: pos * 2 - 1 }
    }

    /// True if the index is pointing at a leaf.
    ///
    /// Every odd number represents a leaf.
    pub fn is_leaf(&self) -> bool {
        self.idx & 1 == 1
    }

    /// Returns the level of the index.
    ///
    /// Starts at level zero for leaves and increases by one for each parent.
    pub fn level(&self) -> u32 {
        self.idx.trailing_zeros()
    }

    /// Returns the index of the left child.
    ///
    /// Panics:
    ///
    /// If the index corresponds to a leaf.
    pub fn left_child(&self) -> InOrderIndex {
        // The left child is itself a parent, with an index that splits its left/right subtrees. To
        // go from the parent index to its left child, it is only necessary to subtract the count
        // of elements on the child's right subtree + 1.
        let els = 1 << (self.level() - 1);
        InOrderIndex { idx: self.idx - els }
    }

    /// Returns the index of the right child.
    ///
    /// Panics:
    ///
    /// If the index corresponds to a leaf.
    pub fn right_child(&self) -> InOrderIndex {
        // To compute the index of the parent of the right subtree it is sufficient to add the size
        // of its left subtree + 1.
        let els = 1 << (self.level() - 1);
        InOrderIndex { idx: self.idx + els }
    }

    /// Returns the index of the parent node.
    pub fn parent(&self) -> InOrderIndex {
        // If the current index corresponds to a node in a left tree, to go up a level it is
        // required to add the number of nodes of the right sibling, analogously if the node is a
        // right child, going up requires subtracting the number of nodes in its left subtree.
        //
        // Both of the above operations can be performed by bitwise manipulation. Below the mask
        // sets the number of trailing zeros to be equal the new level of the index, and the bit
        // marks the parent.
        let target = self.level() + 1;
        let bit = 1 << target;
        let mask = bit - 1;
        let idx = self.idx ^ (self.idx & mask);
        InOrderIndex { idx: idx | bit }
    }

    /// Returns the index of the sibling node.
    pub fn sibling(&self) -> InOrderIndex {
        let parent = self.parent();
        if *self > parent {
            parent.left_child()
        } else {
            parent.right_child()
        }
    }
}

#[cfg(test)]
mod test {
    use super::InOrderIndex;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn proptest_inorder_index_random(count in 1..1000usize) {
            let left_pos = count * 2;
            let right_pos = count * 2 + 1;

            let left = InOrderIndex::from_leaf_pos(left_pos);
            let right = InOrderIndex::from_leaf_pos(right_pos);

            assert!(left.is_leaf());
            assert!(right.is_leaf());
            assert_eq!(left.parent(), right.parent());
            assert_eq!(left.parent().right_child(), right);
            assert_eq!(left, right.parent().left_child());
            assert_eq!(left.sibling(), right);
            assert_eq!(left, right.sibling());
        }
    }

    #[test]
    fn test_inorder_index_basic() {
        let left = InOrderIndex::from_leaf_pos(0);
        let right = InOrderIndex::from_leaf_pos(1);

        assert!(left.is_leaf());
        assert!(right.is_leaf());
        assert_eq!(left.parent(), right.parent());
        assert_eq!(left.parent().right_child(), right);
        assert_eq!(left, right.parent().left_child());
        assert_eq!(left.sibling(), right);
        assert_eq!(left, right.sibling());
    }
}
