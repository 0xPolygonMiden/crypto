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
        if self.is_value_odd() {
            [sibling, slf]
        } else {
            [slf, sibling]
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
    pub const fn is_value_odd(&self) -> bool {
        (self.value & 1) == 1
    }

    /// Returns `true` if the depth is `0`.
    pub const fn is_root(&self) -> bool {
        self.depth == 0
    }

    /// Returns a bit iterator for the `value`.
    ///
    /// Bits read from left-to-right represent which internal node's child should be visited to
    /// arrive at the leaf. From the right-to-left the bit represent the position the hash of the
    /// current element should go.
    ///
    /// Additionally, the value that is not visited are the sibling values necessary for a Merkle
    /// opening.
    pub fn bit_iterator(&self) -> BitIterator {
        let depth: u32 = self.depth.into();
        BitIterator::new(self.value).skip_back(u64::BITS - depth)
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
}
