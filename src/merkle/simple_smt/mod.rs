use super::{
    BTreeMap, BTreeSet, EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, MerkleTreeDelta,
    NodeIndex, Rpo256, RpoDigest, StoreNode, TryApplyDiff, Vec, Word,
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
    branches: BTreeMap<NodeIndex, BranchNode>,
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
    pub fn with_leaves<R, I>(depth: u8, entries: R) -> Result<Self, MerkleError>
    where
        R: IntoIterator<IntoIter = I>,
        I: Iterator<Item = (u64, Word)> + ExactSizeIterator,
    {
        // create an empty tree
        let mut tree = Self::new(depth)?;

        // compute the max number of entries. We use an upper bound of depth 63 because we consider
        // passing in a vector of size 2^64 infeasible.
        let max_num_entries = 2usize.pow(tree.depth.min(63).into());

        // append leaves to the tree returning an error if a duplicate entry for the same key
        // is found
        let mut empty_entries = BTreeSet::new();
        for (key, value) in entries {
            let old_value = tree
                .update_leaf(key, value)
                .map_err(|_| MerkleError::InvalidNumEntries(max_num_entries))?;

            if old_value != Self::EMPTY_VALUE || empty_entries.contains(&key) {
                return Err(MerkleError::DuplicateValuesForIndex(key));
            }
            // if we've processed an empty entry, add the key to the set of empty entry keys, and
            // if this key was already in the set, return an error
            if value == Self::EMPTY_VALUE && !empty_entries.insert(key) {
                return Err(MerkleError::DuplicateValuesForIndex(key));
            }
        }
        Ok(tree)
    }

    /// Wrapper around [`SimpleSmt::with_leaves`] which inserts leaves at contiguous indices
    /// starting at index 0.
    pub fn with_contiguous_leaves<R, I>(depth: u8, entries: R) -> Result<Self, MerkleError>
    where
        R: IntoIterator<IntoIter = I>,
        I: Iterator<Item = Word> + ExactSizeIterator,
    {
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
            Ok(self.get_branch_node(&index).parent())
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
            let BranchNode { left, right } = self.get_branch_node(&index);
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
            value: e.parent(),
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
        let mut idx = NodeIndex::new(self.depth(), index)?;

        let old_value = self.insert_leaf_node(index, value).unwrap_or(Self::EMPTY_VALUE);

        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return Ok(value);
        }

        let mut value = RpoDigest::from(value);
        for _ in 0..idx.depth() {
            let is_right = idx.is_value_odd();
            idx.move_up();
            let BranchNode { left, right } = self.get_branch_node(&idx);
            let (left, right) = if is_right { (left, value) } else { (value, right) };
            self.insert_branch_node(idx, left, right);
            value = Rpo256::merge(&[left, right]);
        }
        self.root = value;
        Ok(old_value)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    fn get_leaf_node(&self, key: u64) -> Option<Word> {
        self.leaves.get(&key).copied()
    }

    fn insert_leaf_node(&mut self, key: u64, node: Word) -> Option<Word> {
        self.leaves.insert(key, node)
    }

    fn get_branch_node(&self, index: &NodeIndex) -> BranchNode {
        self.branches.get(index).cloned().unwrap_or_else(|| {
            let node = EmptySubtreeRoots::entry(self.depth, index.depth() + 1);
            BranchNode { left: *node, right: *node }
        })
    }

    fn insert_branch_node(&mut self, index: NodeIndex, left: RpoDigest, right: RpoDigest) {
        let branch = BranchNode { left, right };
        self.branches.insert(index, branch);
    }
}

// BRANCH NODE
// ================================================================================================

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
struct BranchNode {
    left: RpoDigest,
    right: RpoDigest,
}

impl BranchNode {
    fn parent(&self) -> RpoDigest {
        Rpo256::merge(&[self.left, self.right])
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
