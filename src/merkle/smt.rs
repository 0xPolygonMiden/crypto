use crate::hash::rpo::{Rpo256, RpoDigest};

use super::{MerklePath, NodeIndex};

pub type LeafIndex = u64;

/// An abstract description of a sparse Merkle tree.
///
/// A sparse Merkle tree is a key-value map which also supports proving that a given value is indeed
/// stored at a given key in the tree. It is viewed as always being fully populated. If a leaf's
/// value was not explicitly updated, then its value is the default value. Typically, the vast
/// majority of leaves will store the default value (hence it is "sparse"), and therefore the
/// internal representation of the tree will only keep track of the leaves that have a different
/// value from the default.
///
/// All leaves sit at the same depth. The deeper the tree, the more leaves it has; but also the
/// longer its proofs are - of exactly `log(depth)` size.
///
/// Every key value maps to one leaf. If there are as many keys as there are leaves, then
/// [Self::Leaf] should be the same type as [Self::Value], as is the case with
/// [crate::merkle::SimpleSmt]. However, if there are more keys than leaves, then [`Self::Leaf`]
/// must accomodate all keys that map to the same leaf.
pub trait SparseMerkleTree {
    /// The type for a key, which must be convertible into a `u64` infaillibly
    type Key: Into<LeafIndex>;
    /// The type for a value
    type Value: Default;
    /// The type for a leaf
    type Leaf;

    // PROVIDED METHODS
    // ---------------------------------------------------------------------------------------------

    /// Returns a Merkle path from the leaf node specified by the key to the root.
    ///
    /// The node itself is not included in the path.
    fn get_merkle_path(&self, key: &Self::Key) -> MerklePath {
        todo!()
    }

    /// Updates value of the leaf at the specified index returning the old leaf value.
    ///
    /// This also recomputes all hashes between the leaf and the root, updating the root itself.
    fn update_leaf_at(&mut self, key: &Self::Key, value: Self::Value) -> Self::Value {
        todo!()
    }

    // ABSTRACT METHODS
    // ---------------------------------------------------------------------------------------------

    /// The root of the tree
    fn root(&self) -> RpoDigest;

    /// The depth of the tree
    fn depth(&self) -> u8;

    /// Retrieves an inner node at the given index
    fn get_inner_node(&self, index: NodeIndex) -> InnerNode;

    /// Inserts a leaf node, and returns the value at the key if already exists
    fn insert_leaf_node(&self, key: Self::Key, value: Self::Value) -> Option<Self::Value>;

    /// Returns the hash of a leaf
    fn hash_leaf(v: Self::Leaf) -> RpoDigest;
}

// TODO: Reconcile somehow with `simple_smt::BranchNode`
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct InnerNode {
    left: RpoDigest,
    right: RpoDigest,
}

impl InnerNode {
    pub fn hash(&self) -> RpoDigest {
        Rpo256::merge(&[self.left, self.right])
    }
}
