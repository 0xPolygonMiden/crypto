use winter_math::StarkField;

use crate::{
    hash::rpo::{Rpo256, RpoDigest},
    Word,
};

use super::{MerkleError, MerklePath, NodeIndex, Vec};

// CONSTANTS
// ================================================================================================

/// Minimum supported depth.
pub const SMT_MIN_DEPTH: u8 = 1;

/// Maximum supported depth.
pub const SMT_MAX_DEPTH: u8 = 64;

// SPARSE MERKLE TREE
// ================================================================================================

/// An abstract description of a sparse Merkle tree.
///
/// A sparse Merkle tree is a key-value map which also supports proving that a given value is indeed
/// stored at a given key in the tree. It is viewed as always being fully populated. If a leaf's
/// value was not explicitly set, then its value is the default value. Typically, the vast majority
/// of leaves will store the default value (hence it is "sparse"), and therefore the internal
/// representation of the tree will only keep track of the leaves that have a different value from
/// the default.
///
/// All leaves sit at the same depth. The deeper the tree, the more leaves it has; but also the
/// longer its proofs are - of exactly `log(depth)` size. A tree cannot have depth 0, since such a
/// tree is just a single value, and is probably a programming mistake.
///
/// Every key maps to one leaf. If there are as many keys as there are leaves, then
/// [Self::Leaf] should be the same type as [Self::Value], as is the case with
/// [crate::merkle::SimpleSmt]. However, if there are more keys than leaves, then [`Self::Leaf`]
/// must accomodate all keys that map to the same leaf.
///
/// [SparseMerkleTree] currently doesn't support optimizations that compress Merkle proofs.
pub trait SparseMerkleTree<const DEPTH: u8> {
    /// The type for a key, which must be convertible into a `u64` infaillibly
    type Key: Into<LeafIndex<DEPTH>> + Clone;
    /// The type for a value
    type Value: Clone + PartialEq;
    /// The type for a leaf
    type Leaf;

    /// The default value used to compute the hash of empty leaves
    const EMPTY_VALUE: Self::Value;

    // PROVIDED METHODS
    // ---------------------------------------------------------------------------------------------

    /// Returns a Merkle path from the leaf node specified by the key to the root.
    ///
    /// The node itself is not included in the path.
    fn get_leaf_path(&self, key: Self::Key) -> MerklePath {
        let mut index: NodeIndex = {
            let leaf_index: LeafIndex<DEPTH> = key.into();
            leaf_index.into()
        };

        let mut path = Vec::with_capacity(index.depth() as usize);
        for _ in 0..index.depth() {
            let is_right = index.is_value_odd();
            index.move_up();
            let InnerNode { left, right } = self.get_inner_node(index);
            let value = if is_right { left } else { right };
            path.push(value);
        }

        MerklePath::new(path)
    }

    /// Updates value of the leaf at the specified index returning the old leaf value.
    ///
    /// This also recomputes all hashes between the leaf and the root, updating the root itself.
    fn update_leaf(&mut self, key: Self::Key, value: Self::Value) -> Self::Value {
        let old_value = self.insert_value(key.clone(), value.clone()).unwrap_or(Self::EMPTY_VALUE);

        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return value;
        }

        let leaf = self.get_leaf(&key);
        let node_index = {
            let leaf_index: LeafIndex<DEPTH> = key.into();
            leaf_index.into()
        };

        self.recompute_nodes_from_index_to_root(node_index, Self::hash_leaf(&leaf));

        old_value
    }

    /// Recomputes the branch nodes (including the root) from `index` all the way to the root.
    /// `node_hash_at_index` is the hash of the node stored at index.
    fn recompute_nodes_from_index_to_root(
        &mut self,
        mut index: NodeIndex,
        node_hash_at_index: RpoDigest,
    ) {
        let mut value = node_hash_at_index;
        for _ in 0..index.depth() {
            let is_right = index.is_value_odd();
            index.move_up();
            let InnerNode { left, right } = self.get_inner_node(index);
            let (left, right) = if is_right { (left, value) } else { (value, right) };
            self.insert_inner_node(index, InnerNode { left, right });
            value = Rpo256::merge(&[left, right]);
        }
        self.set_root(value);
    }

    /// Returns the depth of the sparse Merkle tree
    fn depth(&self) -> u8 {
        DEPTH
    }

    // REQUIRED METHODS
    // ---------------------------------------------------------------------------------------------

    /// The root of the tree
    fn root(&self) -> RpoDigest;

    /// Sets the root of the tree
    fn set_root(&mut self, root: RpoDigest);

    /// Retrieves an inner node at the given index
    fn get_inner_node(&self, index: NodeIndex) -> InnerNode;

    /// Inserts an inner node at the given index
    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode);

    /// Inserts a leaf node, and returns the value at the key if already exists
    fn insert_value(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value>;

    /// Returns the leaf at the specified index.
    fn get_leaf(&self, key: &Self::Key) -> Self::Leaf;

    /// Returns the hash of a leaf
    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest;
}

// INNER NODE
// ================================================================================================

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct InnerNode {
    pub left: RpoDigest,
    pub right: RpoDigest,
}

impl InnerNode {
    pub fn hash(&self) -> RpoDigest {
        Rpo256::merge(&[self.left, self.right])
    }
}

// LEAF INDEX
// ================================================================================================

/// The index of a leaf, at a depth known at compile-time.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct LeafIndex<const DEPTH: u8> {
    index: NodeIndex,
}

impl<const DEPTH: u8> LeafIndex<DEPTH> {
    pub fn new(value: u64) -> Result<Self, MerkleError> {
        if DEPTH < SMT_MIN_DEPTH {
            return Err(MerkleError::DepthTooSmall(DEPTH));
        }

        Ok(LeafIndex { index: NodeIndex::new(DEPTH, value)? })
    }

    pub fn value(&self) -> u64 {
        self.index.value()
    }
}

impl LeafIndex<SMT_MAX_DEPTH> {
    pub fn new_max_depth(value: u64) -> Self {
        LeafIndex {
            index: NodeIndex::new_unchecked(SMT_MAX_DEPTH, value),
        }
    }
}

impl<const DEPTH: u8> From<LeafIndex<DEPTH>> for NodeIndex {
    fn from(value: LeafIndex<DEPTH>) -> Self {
        value.index
    }
}

impl<const DEPTH: u8> TryFrom<NodeIndex> for LeafIndex<DEPTH> {
    type Error = MerkleError;

    fn try_from(node_index: NodeIndex) -> Result<Self, Self::Error> {
        if node_index.depth() != DEPTH {
            return Err(MerkleError::InvalidDepth {
                expected: DEPTH,
                provided: node_index.depth(),
            });
        }

        Self::new(node_index.value())
    }
}

impl From<Word> for LeafIndex<SMT_MAX_DEPTH> {
    fn from(value: Word) -> Self {
        // We use the most significant `Felt` of a `Word` as the leaf index.
        Self::new_max_depth(value[3].as_int())
    }
}
