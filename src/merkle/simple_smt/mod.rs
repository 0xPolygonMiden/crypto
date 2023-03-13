use super::{
    BTreeMap, EmptySubtreeRoots, MerkleError, MerklePath, NodeIndex, Rpo256, RpoDigest, Vec, Word,
};

#[cfg(test)]
mod tests;

// SPARSE MERKLE TREE
// ================================================================================================

/// A sparse Merkle tree with 63-bit keys and 4-element leaf values, without compaction.
/// Manipulation and retrieval of leaves and internal nodes is provided by its internal `Store`.
/// The root of the tree is recomputed on each new leaf update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleSmt {
    root: Word,
    depth: u8,
    pub(crate) store: Store,
}

impl SimpleSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Minimum supported depth.
    pub const MIN_DEPTH: u8 = 1;

    /// Maximum supported depth.
    pub const MAX_DEPTH: u8 = 63;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new simple SMT with the provided depth.
    pub fn new(depth: u8) -> Result<Self, MerkleError> {
        // validate the range of the depth.
        if depth < Self::MIN_DEPTH {
            return Err(MerkleError::DepthTooSmall(depth));
        } else if Self::MAX_DEPTH < depth {
            return Err(MerkleError::DepthTooBig(depth as u64));
        }

        let (store, root) = Store::new(depth);
        Ok(Self { root, depth, store })
    }

    /// Appends the provided entries as leaves of the tree.
    ///
    /// # Errors
    ///
    /// The function will fail if the provided entries count exceed the maximum tree capacity, that
    /// is `2^{depth}`.
    pub fn with_leaves<R, I>(mut self, entries: R) -> Result<Self, MerkleError>
    where
        R: IntoIterator<IntoIter = I>,
        I: Iterator<Item = (u64, Word)> + ExactSizeIterator,
    {
        // check if the leaves count will fit the depth setup
        let mut entries = entries.into_iter();
        let max = 1 << self.depth;
        if entries.len() > max {
            return Err(MerkleError::InvalidEntriesCount(max, entries.len()));
        }

        // append leaves and return
        entries.try_for_each(|(key, leaf)| self.insert_leaf(key, leaf))?;
        Ok(self)
    }

    /// Replaces the internal empty digests used when a given depth doesn't contain a node.
    pub fn with_empty_subtrees<I>(mut self, hashes: I) -> Self
    where
        I: IntoIterator<Item = RpoDigest>,
    {
        self.store
            .replace_empty_subtrees(hashes.into_iter().collect());
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of this Merkle tree.
    pub const fn root(&self) -> Word {
        self.root
    }

    /// Returns the depth of this Merkle tree.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Returns the set count of the keys of the leaves.
    pub fn leaves_count(&self) -> usize {
        self.store.leaves_count()
    }

    /// Returns a node at the specified key
    ///
    /// # Errors
    /// Returns an error if:
    /// * The specified depth is greater than the depth of the tree.
    pub fn get_node(&self, index: &NodeIndex) -> Result<Word, MerkleError> {
        if index.is_root() {
            Err(MerkleError::DepthTooSmall(index.depth()))
        } else if index.depth() > self.depth() {
            Err(MerkleError::DepthTooBig(index.depth() as u64))
        } else if index.depth() == self.depth() {
            self.store
                .get_leaf_node(index.value())
                .or_else(|| {
                    self.store
                        .empty_hashes
                        .get(index.depth() as usize)
                        .copied()
                        .map(Word::from)
                })
                .ok_or(MerkleError::InvalidIndex(*index))
        } else {
            let branch_node = self.store.get_branch_node(index);
            Ok(Rpo256::merge(&[branch_node.left, branch_node.right]).into())
        }
    }

    /// Returns a Merkle path from the node at the specified key to the root. The node itself is
    /// not included in the path.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The specified depth is greater than the depth of the tree.
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
            let BranchNode { left, right } = self.store.get_branch_node(&index);
            let value = if is_right { left } else { right };
            path.push(*value);
        }
        Ok(path.into())
    }

    /// Return a Merkle path from the leaf at the specified key to the root. The leaf itself is not
    /// included in the path.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The specified key does not exist as a leaf node.
    pub fn get_leaf_path(&self, key: u64) -> Result<MerklePath, MerkleError> {
        self.get_path(NodeIndex::new(self.depth(), key))
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Replaces the leaf located at the specified key, and recomputes hashes by walking up the tree
    ///
    /// # Errors
    /// Returns an error if the specified key is not a valid leaf index for this tree.
    pub fn update_leaf(&mut self, key: u64, value: Word) -> Result<(), MerkleError> {
        if !self.store.check_leaf_node_exists(key) {
            return Err(MerkleError::InvalidIndex(NodeIndex::new(self.depth(), key)));
        }
        self.insert_leaf(key, value)?;

        Ok(())
    }

    /// Inserts a leaf located at the specified key, and recomputes hashes by walking up the tree
    pub fn insert_leaf(&mut self, key: u64, value: Word) -> Result<(), MerkleError> {
        self.store.insert_leaf_node(key, value);

        // TODO consider using a map `index |-> word` instead of `index |-> (word, word)`
        let mut index = NodeIndex::new(self.depth(), key);
        let mut value = RpoDigest::from(value);
        for _ in 0..index.depth() {
            let is_right = index.is_value_odd();
            index.move_up();
            let BranchNode { left, right } = self.store.get_branch_node(&index);
            let (left, right) = if is_right {
                (left, value)
            } else {
                (value, right)
            };
            self.store.insert_branch_node(index, left, right);
            value = Rpo256::merge(&[left, right]);
        }
        self.root = value.into();
        Ok(())
    }
}

// STORE
// ================================================================================================

/// A data store for sparse Merkle tree key-value pairs.
/// Leaves and branch nodes are stored separately in B-tree maps, indexed by key and (key, depth)
/// respectively. Hashes for blank subtrees at each layer are stored in `empty_hashes`, beginning
/// with the root hash of an empty tree, and ending with the zero value of a leaf node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Store {
    pub(crate) branches: BTreeMap<NodeIndex, BranchNode>,
    leaves: BTreeMap<u64, Word>,
    pub(crate) empty_hashes: Vec<RpoDigest>,
    depth: u8,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BranchNode {
    pub(crate) left: RpoDigest,
    pub(crate) right: RpoDigest,
}

impl Store {
    fn new(depth: u8) -> (Self, Word) {
        let branches = BTreeMap::new();
        let leaves = BTreeMap::new();

        // Construct empty node digests for each layer of the tree
        let empty_hashes = EmptySubtreeRoots::empty_hashes(depth).to_vec();

        let root = empty_hashes[0].into();
        let store = Self {
            branches,
            leaves,
            empty_hashes,
            depth,
        };

        (store, root)
    }

    fn replace_empty_subtrees(&mut self, hashes: Vec<RpoDigest>) {
        self.empty_hashes = hashes;
    }

    fn check_leaf_node_exists(&self, key: u64) -> bool {
        self.leaves.contains_key(&key)
    }

    fn get_leaf_node(&self, key: u64) -> Option<Word> {
        self.leaves.get(&key).copied()
    }

    fn insert_leaf_node(&mut self, key: u64, node: Word) {
        self.leaves.insert(key, node);
    }

    fn get_branch_node(&self, index: &NodeIndex) -> BranchNode {
        self.branches.get(index).cloned().unwrap_or_else(|| {
            let node = self.empty_hashes[index.depth() as usize + 1];
            BranchNode {
                left: node,
                right: node,
            }
        })
    }

    fn insert_branch_node(&mut self, index: NodeIndex, left: RpoDigest, right: RpoDigest) {
        let branch = BranchNode { left, right };
        self.branches.insert(index, branch);
    }

    fn leaves_count(&self) -> usize {
        self.leaves.len()
    }
}
