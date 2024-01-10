use super::{
    BTreeMap, BTreeSet, EmptySubtreeRoots, InnerNode, InnerNodeInfo, MerkleError, MerklePath,
    MerkleTreeDelta, NodeIndex, Rpo256, RpoDigest, StoreNode, TryApplyDiff, Vec, Word,
};

#[cfg(test)]
mod tests;

// SPARSE MERKLE TREE
// ================================================================================================

/// A sparse Merkle tree with 64-bit keys and 4-element leaf values, without compaction.
///
/// The root of the tree is recomputed on each new leaf update.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SimpleSmt {
    depth: u8,
    root: RpoDigest,
    leaves: BTreeMap<u64, Word>,
    branches: BTreeMap<NodeIndex, InnerNode>,
}

impl SimpleSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Minimum supported depth.
    pub const MIN_DEPTH: u8 = 1;

    /// Maximum supported depth.
    pub const MAX_DEPTH: u8 = 64;

    /// Value of an empty leaf.
    pub const EMPTY_VALUE: Word = super::EMPTY_WORD;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [SimpleSmt] instantiated with the specified depth.
    ///
    /// All leaves in the returned tree are set to [ZERO; 4].
    ///
    /// # Errors
    /// Returns an error if the depth is 0 or is greater than 64.
    pub fn new(depth: u8) -> Result<Self, MerkleError> {
        // validate the range of the depth.
        if depth < Self::MIN_DEPTH {
            return Err(MerkleError::DepthTooSmall(depth));
        } else if Self::MAX_DEPTH < depth {
            return Err(MerkleError::DepthTooBig(depth as u64));
        }

        let root = *EmptySubtreeRoots::entry(depth, 0);

        Ok(Self {
            root,
            depth,
            leaves: BTreeMap::new(),
            branches: BTreeMap::new(),
        })
    }

    /// Returns a new [SimpleSmt] instantiated with the specified depth and with leaves
    /// set as specified by the provided entries.
    ///
    /// All leaves omitted from the entries list are set to [ZERO; 4].
    ///
    /// # Errors
    /// Returns an error if:
    /// - If the depth is 0 or is greater than 64.
    /// - The number of entries exceeds the maximum tree capacity, that is 2^{depth}.
    /// - The provided entries contain multiple values for the same key.
    pub fn with_leaves(
        depth: u8,
        entries: impl IntoIterator<Item = (u64, Word)>,
    ) -> Result<Self, MerkleError> {
        // create an empty tree
        let mut tree = Self::new(depth)?;

        // compute the max number of entries. We use an upper bound of depth 63 because we consider
        // passing in a vector of size 2^64 infeasible.
        let max_num_entries = 2_usize.pow(tree.depth.min(63).into());

        // This being a sparse data structure, the EMPTY_WORD is not assigned to the `BTreeMap`, so
        // entries with the empty value need additional tracking.
        let mut key_set_to_zero = BTreeSet::new();

        for (idx, (key, value)) in entries.into_iter().enumerate() {
            if idx >= max_num_entries {
                return Err(MerkleError::InvalidNumEntries(max_num_entries));
            }

            let old_value = tree.update_leaf(key, value)?;

            if old_value != Self::EMPTY_VALUE || key_set_to_zero.contains(&key) {
                return Err(MerkleError::DuplicateValuesForIndex(key));
            }

            if value == Self::EMPTY_VALUE {
                key_set_to_zero.insert(key);
            };
        }
        Ok(tree)
    }

    /// Wrapper around [`SimpleSmt::with_leaves`] which inserts leaves at contiguous indices
    /// starting at index 0.
    pub fn with_contiguous_leaves(
        depth: u8,
        entries: impl IntoIterator<Item = Word>,
    ) -> Result<Self, MerkleError> {
        Self::with_leaves(
            depth,
            entries
                .into_iter()
                .enumerate()
                .map(|(idx, word)| (idx.try_into().expect("tree max depth is 2^8"), word)),
        )
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of this Merkle tree.
    pub const fn root(&self) -> RpoDigest {
        self.root
    }

    /// Returns the depth of this Merkle tree.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns a node at the specified index.
    ///
    /// # Errors
    /// Returns an error if the specified index has depth set to 0 or the depth is greater than
    /// the depth of this Merkle tree.
    pub fn get_node(&self, index: NodeIndex) -> Result<RpoDigest, MerkleError> {
        if index.is_root() {
            Err(MerkleError::DepthTooSmall(index.depth()))
        } else if index.depth() > self.depth() {
            Err(MerkleError::DepthTooBig(index.depth() as u64))
        } else if index.depth() == self.depth() {
            // the lookup in empty_hashes could fail only if empty_hashes were not built correctly
            // by the constructor as we check the depth of the lookup above.
            let leaf_pos = index.value();
            let leaf = match self.get_leaf_node(leaf_pos) {
                Some(word) => word.into(),
                None => *EmptySubtreeRoots::entry(self.depth, index.depth()),
            };
            Ok(leaf)
        } else {
            Ok(self.get_branch_node(&index).hash())
        }
    }

    /// Returns a value of the leaf at the specified index.
    ///
    /// # Errors
    /// Returns an error if the index is greater than the maximum tree capacity, that is 2^{depth}.
    pub fn get_leaf(&self, index: u64) -> Result<Word, MerkleError> {
        let index = NodeIndex::new(self.depth, index)?;
        Ok(self.get_node(index)?.into())
    }

    /// Returns a Merkle path from the node at the specified index to the root.
    ///
    /// The node itself is not included in the path.
    ///
    /// # Errors
    /// Returns an error if the specified index has depth set to 0 or the depth is greater than
    /// the depth of this Merkle tree.
    pub fn get_path(&self, mut index: NodeIndex) -> Result<MerklePath, MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > self.depth() {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        }

        let mut path = Vec::with_capacity(index.depth() as usize);
        for _ in 0..index.depth() {
            let is_right = index.is_value_odd();
            index.move_up();
            let InnerNode { left, right } = self.get_branch_node(&index);
            let value = if is_right { left } else { right };
            path.push(value);
        }
        Ok(MerklePath::new(path))
    }

    /// Return a Merkle path from the leaf at the specified index to the root.
    ///
    /// The leaf itself is not included in the path.
    ///
    /// # Errors
    /// Returns an error if the index is greater than the maximum tree capacity, that is 2^{depth}.
    pub fn get_leaf_path(&self, index: u64) -> Result<MerklePath, MerkleError> {
        let index = NodeIndex::new(self.depth(), index)?;
        self.get_path(index)
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [SimpleSmt].
    pub fn leaves(&self) -> impl Iterator<Item = (u64, &Word)> {
        self.leaves.iter().map(|(i, w)| (*i, w))
    }

    /// Returns an iterator over the inner nodes of this Merkle tree.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.branches.values().map(|e| InnerNodeInfo {
            value: e.hash(),
            left: e.left,
            right: e.right,
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Updates value of the leaf at the specified index returning the old leaf value.
    ///
    /// This also recomputes all hashes between the leaf and the root, updating the root itself.
    ///
    /// # Errors
    /// Returns an error if the index is greater than the maximum tree capacity, that is 2^{depth}.
    pub fn update_leaf(&mut self, index: u64, value: Word) -> Result<Word, MerkleError> {
        // validate the index before modifying the structure
        let idx = NodeIndex::new(self.depth(), index)?;

        let old_value = self.insert_leaf_node(index, value).unwrap_or(Self::EMPTY_VALUE);

        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return Ok(value);
        }

        self.recompute_nodes_from_index_to_root(idx, RpoDigest::from(value));

        Ok(old_value)
    }

    /// Inserts a subtree at the specified index. The depth at which the subtree is inserted is
    /// computed as `self.depth() - subtree.depth()`.
    ///
    /// Returns the new root.
    pub fn set_subtree(
        &mut self,
        subtree_insertion_index: u64,
        subtree: SimpleSmt,
    ) -> Result<RpoDigest, MerkleError> {
        if subtree.depth() > self.depth() {
            return Err(MerkleError::InvalidSubtreeDepth {
                subtree_depth: subtree.depth(),
                tree_depth: self.depth(),
            });
        }

        // Verify that `subtree_insertion_index` is valid.
        let subtree_root_insertion_depth = self.depth() - subtree.depth();
        let subtree_root_index =
            NodeIndex::new(subtree_root_insertion_depth, subtree_insertion_index)?;

        // add leaves
        // --------------

        // The subtree's leaf indices live in their own context - i.e. a subtree of depth `d`. If we
        // insert the subtree at `subtree_insertion_index = 0`, then the subtree leaf indices are
        // valid as they are. However, consider what happens when we insert at
        // `subtree_insertion_index = 1`. The first leaf of our subtree now will have index `2^d`;
        // you can see it as there's a full subtree sitting on its left. In general, for
        // `subtree_insertion_index = i`, there are `i` subtrees sitting before the subtree we want
        // to insert, so we need to adjust all its leaves by `i * 2^d`.
        let leaf_index_shift: u64 = subtree_insertion_index * 2_u64.pow(subtree.depth().into());
        for (subtree_leaf_idx, leaf_value) in subtree.leaves() {
            let new_leaf_idx = leaf_index_shift + subtree_leaf_idx;
            debug_assert!(new_leaf_idx < 2_u64.pow(self.depth().into()));

            self.insert_leaf_node(new_leaf_idx, *leaf_value);
        }

        // add subtree's branch nodes (which includes the root)
        // --------------
        for (branch_idx, branch_node) in subtree.branches {
            let new_branch_idx = {
                let new_depth = subtree_root_insertion_depth + branch_idx.depth();
                let new_value = subtree_insertion_index * 2_u64.pow(branch_idx.depth().into())
                    + branch_idx.value();

                NodeIndex::new(new_depth, new_value).expect("index guaranteed to be valid")
            };

            self.branches.insert(new_branch_idx, branch_node);
        }

        // recompute nodes starting from subtree root
        // --------------
        self.recompute_nodes_from_index_to_root(subtree_root_index, subtree.root);

        Ok(self.root)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

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
            let InnerNode { left, right } = self.get_branch_node(&index);
            let (left, right) = if is_right { (left, value) } else { (value, right) };
            self.insert_branch_node(index, left, right);
            value = Rpo256::merge(&[left, right]);
        }
        self.root = value;
    }

    fn get_leaf_node(&self, key: u64) -> Option<Word> {
        self.leaves.get(&key).copied()
    }

    fn insert_leaf_node(&mut self, key: u64, node: Word) -> Option<Word> {
        self.leaves.insert(key, node)
    }

    fn get_branch_node(&self, index: &NodeIndex) -> InnerNode {
        self.branches.get(index).cloned().unwrap_or_else(|| {
            let node = EmptySubtreeRoots::entry(self.depth, index.depth() + 1);
            InnerNode { left: *node, right: *node }
        })
    }

    fn insert_branch_node(&mut self, index: NodeIndex, left: RpoDigest, right: RpoDigest) {
        let branch = InnerNode { left, right };
        self.branches.insert(index, branch);
    }
}

// TRY APPLY DIFF
// ================================================================================================
impl TryApplyDiff<RpoDigest, StoreNode> for SimpleSmt {
    type Error = MerkleError;
    type DiffType = MerkleTreeDelta;

    fn try_apply(&mut self, diff: MerkleTreeDelta) -> Result<(), MerkleError> {
        if diff.depth() != self.depth() {
            return Err(MerkleError::InvalidDepth {
                expected: self.depth(),
                provided: diff.depth(),
            });
        }

        for slot in diff.cleared_slots() {
            self.update_leaf(*slot, Self::EMPTY_VALUE)?;
        }

        for (slot, value) in diff.updated_slots() {
            self.update_leaf(*slot, *value)?;
        }

        Ok(())
    }
}
