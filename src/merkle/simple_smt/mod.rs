use super::{
    smt::SMT_MAX_DEPTH, BTreeMap, BTreeSet, EmptySubtreeRoots, InnerNode, InnerNodeInfo, LeafIndex,
    MerkleError, MerkleTreeDelta, NodeIndex, RpoDigest, SparseMerkleTree, StoreNode, TryApplyDiff,
    Word, SMT_MIN_DEPTH,
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Value of an empty leaf.
pub const EMPTY_VALUE: Word = super::EMPTY_WORD;

// SPARSE MERKLE TREE
// ================================================================================================

/// A sparse Merkle tree with 64-bit keys and 4-element leaf values, without compaction.
///
/// The root of the tree is recomputed on each new leaf update.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SimpleSmt<const DEPTH: u8> {
    root: RpoDigest,
    leaves: BTreeMap<u64, Word>,
    inner_nodes: BTreeMap<NodeIndex, InnerNode>,
}

impl<const DEPTH: u8> SimpleSmt<DEPTH> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [SimpleSmt] instantiated with the specified depth.
    ///
    /// All leaves in the returned tree are set to [ZERO; 4].
    ///
    /// # Errors
    /// Returns an error if the depth is 0 or is greater than 64.
    pub fn new() -> Result<Self, MerkleError> {
        // validate the range of the depth.
        if DEPTH < SMT_MIN_DEPTH {
            return Err(MerkleError::DepthTooSmall(DEPTH));
        } else if SMT_MAX_DEPTH < DEPTH {
            return Err(MerkleError::DepthTooBig(DEPTH as u64));
        }

        let root = *EmptySubtreeRoots::entry(DEPTH, 0);

        Ok(Self {
            root,
            leaves: BTreeMap::new(),
            inner_nodes: BTreeMap::new(),
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
        entries: impl IntoIterator<Item = (u64, Word)>,
    ) -> Result<Self, MerkleError> {
        // create an empty tree
        let mut tree = Self::new()?;

        // compute the max number of entries. We use an upper bound of depth 63 because we consider
        // passing in a vector of size 2^64 infeasible.
        let max_num_entries = 2_usize.pow(tree.depth().min(63).into());

        // This being a sparse data structure, the EMPTY_WORD is not assigned to the `BTreeMap`, so
        // entries with the empty value need additional tracking.
        let mut key_set_to_zero = BTreeSet::new();

        for (idx, (key, value)) in entries.into_iter().enumerate() {
            if idx >= max_num_entries {
                return Err(MerkleError::InvalidNumEntries(max_num_entries));
            }

            let old_value = tree.update_leaf(LeafIndex::<DEPTH>::new(key)?, value);

            if old_value != EMPTY_VALUE || key_set_to_zero.contains(&key) {
                return Err(MerkleError::DuplicateValuesForIndex(key));
            }

            if value == EMPTY_VALUE {
                key_set_to_zero.insert(key);
            };
        }
        Ok(tree)
    }

    /// Wrapper around [`SimpleSmt::with_leaves`] which inserts leaves at contiguous indices
    /// starting at index 0.
    pub fn with_contiguous_leaves(
        entries: impl IntoIterator<Item = Word>,
    ) -> Result<Self, MerkleError> {
        Self::with_leaves(
            entries
                .into_iter()
                .enumerate()
                .map(|(idx, word)| (idx.try_into().expect("tree max depth is 2^8"), word)),
        )
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of this Merkle tree.
    pub const fn depth(&self) -> u8 {
        DEPTH
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
            let leaf = self.get_leaf(&LeafIndex::<DEPTH>::try_from(index)?);

            Ok(leaf.into())
        } else {
            Ok(self.get_inner_node(index).hash())
        }
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [SimpleSmt].
    pub fn leaves(&self) -> impl Iterator<Item = (u64, &Word)> {
        self.leaves.iter().map(|(i, w)| (*i, w))
    }

    /// Returns an iterator over the inner nodes of this Merkle tree.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.inner_nodes.values().map(|e| InnerNodeInfo {
            value: e.hash(),
            left: e.left,
            right: e.right,
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a subtree at the specified index. The depth at which the subtree is inserted is
    /// computed as `self.depth() - subtree.depth()`.
    ///
    /// Returns the new root.
    pub fn set_subtree<const SUBTREE_DEPTH: u8>(
        &mut self,
        subtree_insertion_index: u64,
        subtree: SimpleSmt<SUBTREE_DEPTH>,
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

            self.leaves.insert(new_leaf_idx, *leaf_value);
        }

        // add subtree's branch nodes (which includes the root)
        // --------------
        for (branch_idx, branch_node) in subtree.inner_nodes {
            let new_branch_idx = {
                let new_depth = subtree_root_insertion_depth + branch_idx.depth();
                let new_value = subtree_insertion_index * 2_u64.pow(branch_idx.depth().into())
                    + branch_idx.value();

                NodeIndex::new(new_depth, new_value).expect("index guaranteed to be valid")
            };

            self.inner_nodes.insert(new_branch_idx, branch_node);
        }

        // recompute nodes starting from subtree root
        // --------------
        self.recompute_nodes_from_index_to_root(subtree_root_index, subtree.root);

        Ok(self.root)
    }
}

impl<const DEPTH: u8> SparseMerkleTree<DEPTH> for SimpleSmt<DEPTH> {
    type Key = LeafIndex<DEPTH>;
    type Value = Word;
    type Leaf = Word;

    fn root(&self) -> RpoDigest {
        self.root
    }

    fn set_root(&mut self, root: RpoDigest) {
        self.root = root;
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        self.inner_nodes.get(&index).cloned().unwrap_or_else(|| {
            let node = EmptySubtreeRoots::entry(self.depth(), index.depth() + 1);

            InnerNode { left: *node, right: *node }
        })
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) {
        self.inner_nodes.insert(index, inner_node);
    }

    fn insert_leaf_node(&mut self, key: LeafIndex<DEPTH>, value: Word) -> Option<Word> {
        self.leaves.insert(key.value(), value)
    }

    fn get_leaf(&self, key: &LeafIndex<DEPTH>) -> Word {
        // the lookup in empty_hashes could fail only if empty_hashes were not built correctly
        // by the constructor as we check the depth of the lookup above.
        let leaf_pos = key.value();

        match self.leaves.get(&leaf_pos) {
            Some(word) => *word,
            None => Word::from(*EmptySubtreeRoots::entry(self.depth(), self.depth())),
        }
    }

    fn hash_leaf(leaf: &Word) -> RpoDigest {
        // `SimpleSmt` takes the leaf value itself as the hash
        leaf.into()
    }
}

// TRY APPLY DIFF
// ================================================================================================
impl<const DEPTH: u8> TryApplyDiff<RpoDigest, StoreNode> for SimpleSmt<DEPTH> {
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
            self.update_leaf(LeafIndex::<DEPTH>::new(*slot)?, EMPTY_VALUE);
        }

        for (slot, value) in diff.updated_slots() {
            self.update_leaf(LeafIndex::<DEPTH>::new(*slot)?, *value);
        }

        Ok(())
    }
}
