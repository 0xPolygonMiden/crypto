use super::{Felt, MerkleError, RpoDigest, StarkField};
use crate::bit::BitIterator;

// NODE INDEX
// ================================================================================================

/// A Merkle tree address to an arbitrary node.
///
/// The position is relative to a tree in level order, where for a given depth `d` elements are
/// numbered from $0..2^d$.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct NodeIndex {
    depth: u8,
    value: u64,
}

/// Describes the direction a node must go when inserted into a merkle structure.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    Left = 0,
    Right = 1,
}

impl From<bool> for Direction {
    fn from(value: bool) -> Self {
        match value {
            false => Direction::Left,
            true => Direction::Right,
        }
    }
}

impl NodeIndex {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new node index.
    pub const fn new(depth: u8, value: u64) -> Self {
        Self { depth, value }
    }

    /// Creates a node index from a pair of field elements representing the depth and value.
    ///
    /// # Errors
    ///
    /// Will error if the `u64` representation of the depth doesn't fit a `u8`.
    pub fn from_elements(depth: &Felt, value: &Felt) -> Result<Self, MerkleError> {
        let depth = depth.as_int();
        let depth = u8::try_from(depth).map_err(|_| MerkleError::DepthTooBig(depth))?;
        let value = value.as_int();
        Ok(Self::new(depth, value))
    }

    /// Creates a new node index pointing to the root of the tree.
    pub const fn root() -> Self {
        Self { depth: 0, value: 0 }
    }

    /// Mutates the instance and returns it, replacing the depth.
    pub const fn with_depth(mut self, depth: u8) -> Self {
        self.depth = depth;
        self
    }

    /// Computes the value of the sibling of the current node.
    pub fn sibling(mut self) -> Self {
        self.value ^= 1;
        self
    }

    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Builds a node to be used as input of a hash function when computing a Merkle path.
    ///
    /// Will evaluate the parity of the current instance to define the result.
    pub const fn build_node(&self, slf: RpoDigest, sibling: RpoDigest) -> [RpoDigest; 2] {
        match self.direction() {
            Direction::Left => [slf, sibling],
            Direction::Right => [sibling, slf],
        }
    }

    /// Returns the scalar representation of the depth/value pair.
    ///
    /// It is computed as `2^depth + value`.
    pub const fn to_scalar_index(&self) -> u64 {
        (1 << self.depth as u64) + self.value
    }

    /// Returns the depth of the current instance.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns the value of this index.
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Returns true if the current value fits the current depth for a binary tree.
    pub const fn is_valid(&self) -> bool {
        self.value < (1 << self.depth as u64)
    }

    /// Returns true if the current instance points to a right sibling node.
    pub const fn direction(&self) -> Direction {
        if (self.value & 1) == (Direction::Left as u64) {
            Direction::Left
        } else {
            Direction::Right
        }
    }

    /// Returns `true` if the depth is `0`.
    pub const fn is_root(&self) -> bool {
        self.depth == 0
    }

    /// Return a direction iterator for the node when going from leaf-to-root.
    ///
    /// The first `depth` bits of `value`, going from least to most significant, determines the
    /// node's right/left position in a internal node.
    pub fn leaf_to_root(&self) -> impl DoubleEndedIterator<Item = Direction> {
        let depth: u32 = self.depth.into();
        BitIterator::new(self.value)
            .skip_back(u64::BITS - depth)
            .map(|v| v.into())
    }

    /// Return a direction iterator for the node when going from root-to-leaf.
    ///
    /// The first `depth` bits of `value`, going from most to least significant, determines the
    /// node's right/left position in a internal node.
    pub fn root_to_leaf(&self) -> impl DoubleEndedIterator<Item = Direction> {
        self.leaf_to_root().rev()
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Traverse one level towards the root, decrementing the depth by `1`.
    pub fn move_up(&mut self) -> &mut Self {
        self.depth = self.depth.saturating_sub(1);
        self.value >>= 1;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::super::Vec;
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_index_wont_panic_on_move_up(
            depth in prop::num::u8::ANY,
            value in prop::num::u64::ANY,
            count in prop::num::u8::ANY,
        ) {
            let mut index = NodeIndex::new(depth, value);
            for _ in 0..count {
                index.move_up();
            }
        }
    }

    /// Test that using `leaf_to_root` or `move_up` give the same result.
    #[test]
    fn test_node_index_and_leaf_to_root_match() {
        let value = 0b10101010_01010101_11110000_10110111;

        for depth in 1..=64 {
            let mut index = NodeIndex::new(depth, value);

            let bits: Vec<Direction> = index.leaf_to_root().collect();
            let mut indexes: Vec<Direction> = Vec::new();
            for _ in 0..depth {
                indexes.push(index.direction());
                index.move_up();
            }

            assert_eq!(bits, indexes);
        }
    }

    /// Test with the same value and different depths, the smaller depth is a prefix of the larger
    /// one (this allows nodes to be moved up and down in a SMT).
    #[test]
    fn test_increasing_depth_doesnt_change_prefix() {
        let value = 0b10101010_11110000_10110111_01010101;

        // accumulates the new bit on every iteration
        let mut prefix: Vec<Direction> = Vec::new();
        for depth in 1..=64 {
            let mut index = NodeIndex::new(depth.into(), value);

            let bits: Vec<Direction> = index.leaf_to_root().collect();
            let mut indexes: Vec<Direction> = Vec::new();
            for _ in 0..depth {
                indexes.push(index.direction());
                index.move_up();
            }

            assert_eq!(bits, indexes);

            prefix.push(*bits.last().unwrap());
            assert_eq!(prefix.len(), depth.into());

            assert!(bits.iter().zip(prefix.iter()).all(|(l, r)| l == r));
            assert!(indexes.iter().zip(prefix.iter()).all(|(l, r)| l == r));
        }
    }
}
