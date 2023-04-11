use super::{Felt, MerkleError, RpoDigest, StarkField};

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

    /// Creates a new node index pointing to the root of the tree.
    pub const fn root() -> Self {
        Self { depth: 0, value: 0 }
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

    #[test]
    fn test_node_index_value_too_high() {
        assert_eq!(NodeIndex::new(0, 0).unwrap(), NodeIndex { depth: 0, value: 0 });
        match NodeIndex::new(0, 1) {
            Err(MerkleError::InvalidIndex { depth, value }) => {
                assert_eq!(depth, 0);
                assert_eq!(value, 1);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_node_index_can_represent_depth_64() {
        assert!(NodeIndex::new(64, u64::MAX).is_ok());
    }

    prop_compose! {
        fn node_index()(value in 0..2u64.pow(u64::BITS - 1)) -> NodeIndex {
            // unwrap never panics because the range of depth is 0..u64::BITS
            let mut depth = value.ilog2() as u8;
            if value > (1 << depth) { // round up
                depth += 1;
            }
            NodeIndex::new(depth, value.into()).unwrap()
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
