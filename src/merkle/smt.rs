use crate::hash::rpo::{Rpo256, RpoDigest};

use super::{MerkleError, MerklePath, NodeIndex};

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
///
/// [SparseMerkleTree] currently doesn't support optimizations that compress Merkle proofs.
pub trait SparseMerkleTree {
    /// The type for a key, which must be convertible into a `u64` infaillibly
    type Key: Into<LeafIndex> + Clone;
    /// The type for a value
    type Value: Clone + Default + PartialEq;
    /// The type for a leaf
    type Leaf;

    // PROVIDED METHODS
    // ---------------------------------------------------------------------------------------------

    /// Returns a Merkle path from the leaf node specified by the key to the root.
    ///
    /// The node itself is not included in the path.
    fn get_merkle_path(&self, key: Self::Key) -> MerklePath {
        todo!()
    }

    /// Updates value of the leaf at the specified index returning the old leaf value.
    ///
    /// This also recomputes all hashes between the leaf and the root, updating the root itself.
    fn update_leaf_at(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<Self::Value, MerkleError> {
        let old_value = self.insert_leaf_node(key.clone(), value.clone()).unwrap_or_default();

        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return Ok(value);
        }

        let idx = NodeIndex::new(self.depth(), key.into())?;
        self.recompute_nodes_from_index_to_root(idx, Self::hash_value(value));

        Ok(old_value)
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

    // ABSTRACT METHODS
    // ---------------------------------------------------------------------------------------------

    /// The root of the tree
    fn root(&self) -> RpoDigest;

    /// Sets the root of the tree
    fn set_root(&mut self, root: RpoDigest);

    /// The depth of the tree
    fn depth(&self) -> u8;

    /// Retrieves an inner node at the given index
    fn get_inner_node(&self, index: NodeIndex) -> InnerNode;

    /// Inserts an inner node at the given index
    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode);

    /// Inserts a leaf node, and returns the value at the key if already exists
    fn insert_leaf_node(&self, key: Self::Key, value: Self::Value) -> Option<Self::Value>;

    /// Returns the hash of a leaf
    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest;

    /// Returns the hash of a value
    /// FIXME: I found no good interface to mean "is hashable into a RpoDigest" that I could apply to `Self::Value`
    fn hash_value(value: Self::Value) -> RpoDigest;
}

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
