use core::{fmt::Display, num::NonZero};

use super::{Felt, MerkleError, RpoDigest};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// NODE INDEX
// ================================================================================================

/// Address to an arbitrary node in a binary tree using level order form.
///
/// The position is represented by the pair `(depth, pos)`, where for a given depth `d` elements
/// are numbered from $0..(2^d)-1$. Example:
///
/// ```ignore
/// depth
/// 0             0
/// 1         0        1
/// 2      0    1    2    3
/// 3     0 1  2 3  4 5  6 7
/// ```
///
/// The root is represented by the pair $(0, 0)$, its left child is $(1, 0)$ and its right child
/// $(1, 1)$.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct NodeIndex {
    depth: u8,
    value: u64,
}

impl NodeIndex {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new node index.
    ///
    /// # Errors
    /// Returns an error if the `value` is greater than or equal to 2^{depth}.
    pub const fn new(depth: u8, value: u64) -> Result<Self, MerkleError> {
        if (64 - value.leading_zeros()) > depth as u32 {
            Err(MerkleError::InvalidIndex { depth, value })
        } else {
            Ok(Self { depth, value })
        }
    }

    /// Creates a new node index without checking its validity.
    pub const fn new_unchecked(depth: u8, value: u64) -> Self {
        debug_assert!((64 - value.leading_zeros()) <= depth as u32);
        Self { depth, value }
    }

    /// Creates a new node index for testing purposes.
    ///
    /// # Panics
    /// Panics if the `value` is greater than or equal to 2^{depth}.
    #[cfg(test)]
    pub fn make(depth: u8, value: u64) -> Self {
        Self::new(depth, value).unwrap()
    }

    /// Creates a node index from a pair of field elements representing the depth and value.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `depth` doesn't fit in a `u8`.
    /// - `value` is greater than or equal to 2^{depth}.
    pub fn from_elements(depth: &Felt, value: &Felt) -> Result<Self, MerkleError> {
        let depth = depth.as_int();
        let depth = u8::try_from(depth).map_err(|_| MerkleError::DepthTooBig(depth))?;
        let value = value.as_int();
        Self::new(depth, value)
    }

    /// Converts a scalar representation of a depth/value pair to a [`NodeIndex`].
    ///
    /// This is the inverse operation of [`NodeIndex::to_scalar_index()`]. As `1` represents the
    /// root node, `index` cannot be zero.
    ///
    /// # Errors
    /// Returns the same errors under the same conditions as [`NodeIndex::new()`].
    ///
    /// # Panics
    /// Panics if the depth indicated by `index` does not fit in a [`u8`], or if the row-value
    /// indicated by `index` does not fit in a [`u64`].
    pub fn from_scalar_index(index: NonZero<u128>) -> Result<Self, MerkleError> {
        let index = index.get() - 1;

        if index == 0 {
            return Ok(Self::root());
        }

        // The log of 1 is always 0.
        if index == 1 {
            return Ok(Self::root().left_child());
        }

        let depth = {
            let depth = u128::ilog2(index + 1);
            assert!(depth <= u8::MAX as u32);
            depth as u8
        };

        let max_value_for_depth = (1 << depth) - 1;
        assert!(
            max_value_for_depth <= u64::MAX as u128,
            "max_value ({max_value_for_depth}) does not fit in u64",
        );

        let value = {
            let value = index - max_value_for_depth;
            assert!(value <= u64::MAX as u128);
            value as u64
        };

        Self::new(depth, value)
    }

    /// Creates a new node index pointing to the root of the tree.
    pub const fn root() -> Self {
        Self { depth: 0, value: 0 }
    }

    /// Computes sibling index of the current node.
    pub const fn sibling(mut self) -> Self {
        self.value ^= 1;
        self
    }

    /// Returns left child index of the current node.
    pub const fn left_child(mut self) -> Self {
        self.depth += 1;
        self.value <<= 1;
        self
    }

    pub const fn left_ancestor_n(mut self, n: u8) -> Self {
        self.depth += n;
        self.value <<= n;
        self
    }

    pub const fn right_ancestor_n(mut self, n: u8) -> Self {
        self.depth += n;
        self.value = (self.value << n) + 1;
        self
    }

    /// Returns right child index of the current node.
    pub const fn right_child(mut self) -> Self {
        self.depth += 1;
        self.value = (self.value << 1) + 1;
        self
    }

    /// Returns the parent of the current node.
    pub const fn parent(mut self) -> Self {
        self.depth = self.depth.saturating_sub(1);
        self.value >>= 1;
        self
    }

    /// Returns the `n`th parent of the current node.
    pub fn parent_n(mut self, n: u8) -> Self {
        debug_assert!(n <= self.depth);
        self.depth = self.depth.saturating_sub(n);
        self.value >>= n;

        self
    }

    /// Returns `true` if and only if `other` is an ancestor of the current node, or the current
    /// node itself.
    pub fn contains(&self, mut other: Self) -> bool {
        if other == *self {
            return true;
        }
        if other.is_root() {
            return false;
        }
        if other.depth < self.depth {
            return false;
        }

        other = other.parent_n(other.depth() - self.depth());

        loop {
            if other == *self {
                return true;
            }

            if other.is_root() {
                return false;
            }

            if other.depth < self.depth {
                return false;
            }

            other = other.parent();
        }
    }

    /// The inverse of [`NodeIndex::is_ancestor_of`], except that it does not include itself.
    pub fn is_descendent_of(self, other: Self) -> bool {
        self.depth != other.depth && self.value != other.value && other.contains(self)
    }

    /// Returns `true` if and only if `other` is an ancestor of the current node.
    pub fn is_ancestor_of(self, other: Self) -> bool {
        self.depth != other.depth && self.value != other.value && self.contains(other)
    }

    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Builds a node to be used as input of a hash function when computing a Merkle path.
    ///
    /// Will evaluate the parity of the current instance to define the result.
    pub const fn build_node(&self, slf: RpoDigest, sibling: RpoDigest) -> [RpoDigest; 2] {
        if self.is_value_odd() {
            [sibling, slf]
        } else {
            [slf, sibling]
        }
    }

    /// Returns the scalar representation of the depth/value pair.
    ///
    /// It is computed as `2^depth + value`.
    pub const fn to_scalar_index(&self) -> u128 {
        (1 << self.depth as u64) + (self.value as u128)
    }

    /// Returns the depth of the current instance.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns the value of this index.
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Returns true if the current instance points to a right sibling node.
    pub const fn is_value_odd(&self) -> bool {
        (self.value & 1) == 1
    }

    /// Returns `true` if the depth is `0`.
    pub const fn is_root(&self) -> bool {
        self.depth == 0
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Traverses one level towards the root, decrementing the depth by `1`.
    pub fn move_up(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        self.value >>= 1;
    }

    /// Traverses towards the root until the specified depth is reached.
    ///
    /// Assumes that the specified depth is smaller than the current depth.
    pub fn move_up_to(&mut self, depth: u8) {
        debug_assert!(depth < self.depth);
        let delta = self.depth.saturating_sub(depth);
        self.depth = self.depth.saturating_sub(delta);
        self.value >>= delta as u32;
    }
}

impl Display for NodeIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "depth={}, value={}", self.depth, self.value)
    }
}

impl Serializable for NodeIndex {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.depth);
        target.write_u64(self.value);
    }
}

impl Deserializable for NodeIndex {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let depth = source.read_u8()?;
        let value = source.read_u64()?;
        NodeIndex::new(depth, value)
            .map_err(|_| DeserializationError::InvalidValue("Invalid index".into()))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn test_node_index_value_too_high() {
        assert_eq!(NodeIndex::new(0, 0).unwrap(), NodeIndex { depth: 0, value: 0 });
        let err = NodeIndex::new(0, 1).unwrap_err();
        assert_eq!(err, MerkleError::InvalidIndex { depth: 0, value: 1 });

        assert_eq!(NodeIndex::new(1, 1).unwrap(), NodeIndex { depth: 1, value: 1 });
        let err = NodeIndex::new(1, 2).unwrap_err();
        assert_eq!(err, MerkleError::InvalidIndex { depth: 1, value: 2 });

        assert_eq!(NodeIndex::new(2, 3).unwrap(), NodeIndex { depth: 2, value: 3 });
        let err = NodeIndex::new(2, 4).unwrap_err();
        assert_eq!(err, MerkleError::InvalidIndex { depth: 2, value: 4 });

        assert_eq!(NodeIndex::new(3, 7).unwrap(), NodeIndex { depth: 3, value: 7 });
        let err = NodeIndex::new(3, 8).unwrap_err();
        assert_eq!(err, MerkleError::InvalidIndex { depth: 3, value: 8 });
    }

    #[test]
    fn test_node_index_can_represent_depth_64() {
        assert!(NodeIndex::new(64, u64::MAX).is_ok());
    }

    #[test]
    fn test_scalar_roundtrip() {
        // Arbitrary value that's at the bottom and not in a corner.
        let start = NodeIndex::make(64, u64::MAX - 8);

        let mut index = start;
        while !index.is_root() {
            let as_scalar = index.to_scalar_index();
            let round_trip =
                NodeIndex::from_scalar_index(NonZero::new(as_scalar).unwrap()).unwrap();
            assert_eq!(index, round_trip, "{index:?} did not round-trip as a scalar index");
            index.move_up();
        }
    }

    prop_compose! {
        fn node_index()(value in 0..2u64.pow(u64::BITS - 1)) -> NodeIndex {
            // unwrap never panics because the range of depth is 0..u64::BITS
            let mut depth = value.ilog2() as u8;
            if value > (1 << depth) { // round up
                depth += 1;
            }
            NodeIndex::new(depth, value).unwrap()
        }
    }

    proptest! {
        #[test]
        fn arbitrary_index_wont_panic_on_move_up(
            mut index in node_index(),
            count in prop::num::u8::ANY,
        ) {
            for _ in 0..count {
                index.move_up();
            }
        }
    }
}
