use super::{
    BTreeMap, CanonicalWord, EmptyNodesSubtrees, Felt, MerkleError, MerklePath, NodeIndex, Rpo256,
    RpoDigest, SimpleSmt, Vec, Word,
};
use core::borrow::Borrow;

mod proof;
pub use proof::{LeafProof, LeafProofInput};

mod storage;
pub use storage::Storage;

#[cfg(test)]
mod tests;

// TIERED SPARSE MERKLE TREE
// ================================================================================================

/// A tiered sparse Merkle tree.
///
/// The leaves will be inserted only in predefined depths, and will compose an ordered list of
/// leaves if the collide at the maximum depth of the tree.
#[derive(Debug)]
pub struct TieredSmt {
    storage: Storage,
    root: Word,
}

impl Default for TieredSmt {
    fn default() -> Self {
        Self {
            storage: Default::default(),
            root: EmptyNodesSubtrees::get_node_64(0).into(),
        }
    }
}

impl TieredSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Maximum depth where leaves will be ordered into lists if they collide.
    pub const MAX_DEPTH: u8 = 64;

    /// Node depth of each tier.
    pub const TIER_DEPTH: u8 = 16;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of the tiered sparse Merkle tree with the provided storage backend.
    pub fn with_storage(mut self, storage: Storage) -> Self {
        self.root = storage
            .get_tree(&NodeIndex::root())
            .map(|tree| tree.root())
            .unwrap_or_else(|| EmptyNodesSubtrees::get_node_64(0).into());
        self.storage = storage;
        self
    }

    /// Mutates the tiered sparse Merkle tree, extending its leaves set with the provided argument.
    pub fn with_leaves<I>(self, leaves: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = (Word, Word)>,
    {
        leaves.into_iter().try_fold(self, |mut tree, (key, value)| {
            tree.insert(key, value)?;
            Ok(tree)
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the current Merkle root of the state of the tree.
    pub const fn root(&self) -> &Word {
        &self.root
    }

    /// Returns a tree node or its constant empty subtree for that depth.
    pub fn get_node(&self, index: &NodeIndex) -> Result<Word, MerkleError> {
        if index.depth() > Self::MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        }
        let (subtree, relative) = Self::get_subtree_index(index);
        // TODO we should have a strategy to cache the sub-trees. maybe some LRU? each subtree is
        // expected to consume ~2mb.
        match self.storage.get_tree(&subtree) {
            Some(tree) => tree.get_node(&relative),
            None => Ok(EmptyNodesSubtrees::get_node_64(index.depth()).into()),
        }
    }

    /// Builds a path from the node to the root.
    pub fn get_tier_path(&self, mut index: NodeIndex) -> Result<MerklePath, MerkleError> {
        let mut path = Vec::with_capacity(index.depth() as usize);
        while index.depth() > 0 {
            let (subtree, relative) = Self::get_subtree_index(&index);
            let tree = self.get_tree(&subtree)?;
            let tree_path = tree.get_path(relative)?;
            index.move_up_by(index.depth() - subtree.depth());
            path.extend(tree_path);
        }
        Ok(MerklePath::new(path))
    }

    /// Builds a path from the leaf to the root.
    pub fn get_leaf_path(&self, key: &Word) -> Result<MerklePath, MerkleError> {
        let index = self.get_leaf_index(key);
        self.get_tier_path(index)
    }

    /// Returns the index of the leaf with the specified key.
    ///
    /// If the leaf is not in the tree, returns the index at which it could have been located.
    /// Specifically, this could result in indexes of the following:
    /// - An empty node.
    /// - Another leaf which shares a prefix with the specified key.
    pub fn get_leaf_index(&self, key: &Word) -> NodeIndex {
        let key = CanonicalWord::from(key);

        // if it exists, then return it
        if let Some(index) = self.storage.get_leaf_key(&key).copied() {
            return index;
        }

        // otherwise, traverse until an empty leaf
        let mut depth = Self::TIER_DEPTH;
        while depth < Self::MAX_DEPTH {
            let index = Self::index_from_key(&key, depth);
            if self.is_leaf(&index) || !self.storage.is_subtree_root(&index) {
                return index;
            }
            depth += Self::TIER_DEPTH;
        }
        NodeIndex::new(Self::MAX_DEPTH, key.last_limb())
    }

    /// Computes a leaf proof for the provided key.
    ///
    /// The proof can be used to verify membership and non-membership of the key.
    ///
    /// Note: this function will not assert the validity of the proof as it can verify either
    /// membership or non-membership.
    pub fn get_leaf_proof(&self, key: &Word) -> Result<LeafProof, MerkleError> {
        // compute the node input, depending on the traversed node and depth.
        let index = self.get_leaf_index(key);
        let input = if !self.is_leaf(&index) {
            LeafProofInput::Empty
        } else if index.depth() == Self::MAX_DEPTH {
            self.storage
                .get_bottom_leaves(index.value())
                .cloned()
                .map(LeafProofInput::Lower)
                .unwrap_or_default()
        } else {
            let key = CanonicalWord::from(key);
            self.storage
                .get_leaf_value(&key)
                .copied()
                .map(|value| LeafProofInput::Upper(key, value))
                .unwrap_or_default()
        };

        // return the path with the input commitment
        let path = self.get_tier_path(index)?;
        Ok(LeafProof::new(input, path))
    }

    /// Returns a leaf value indexed by the provided key.
    pub fn get_leaf_value(&self, key: &Word) -> Option<&Word> {
        let key = CanonicalWord::from(key);
        self.storage.get_leaf_value(&key)
    }

    /// Fetch a list of leaves given a bottom tier index.
    pub fn get_bottom_leaves(&self, index: u64) -> Option<&BTreeMap<CanonicalWord, Word>> {
        self.storage.get_bottom_leaves(index)
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Replaces key on the tree, overriding a previous value.
    ///
    /// Returns the new root state.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<&Word, MerkleError> {
        // fetch the filled or empty node of the leaf
        let mut index = self.get_leaf_index(&key);

        // update storage value
        let key = CanonicalWord::from(key);
        self.storage.replace_leaf_value(key, value);

        // promote leaves until they diverge
        // if bottom tier, then we don't need to promote any leaf as it will be just appended to
        // the list
        if self.is_leaf(&index) && index.depth() < Self::MAX_DEPTH {
            let peer = match self.storage.get_lowest_key_at_index(&index).copied() {
                Some(p) => p,
                None => unreachable!("the index is occupied so a leaf must exist"),
            };

            // detach the peer from the current node
            let mut peer_index = match self.storage.take_leaf_key(&peer) {
                Some(i) => i,
                None => unreachable!("a lowest key was found for this index"),
            };
            debug_assert_eq!(peer_index, index);

            // continue traversing until the paths diverge, or bottom
            while index.depth() < Self::MAX_DEPTH && index.value() != peer_index.value() {
                // traverse to next tier
                let depth = index.depth() + Self::TIER_DEPTH;

                // update the indexes for the new depth
                index = Self::index_from_key(&key, depth);
                peer_index = Self::index_from_key(&peer, depth);
            }

            // paths diverged or bottom; update peer path
            // TODO this can be optimized to update up to converging path
            self.update_leaf_path(peer_index, peer)?;
        }

        // conflicting keys are resolved, finish updating the path
        self.update_leaf_path(index, key)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Generate a new sub-tree with root at `depth`.
    fn generate_simple_smt(depth: u8) -> Result<SimpleSmt, MerkleError> {
        let depth = depth as usize;
        let empty_subtrees =
            &EmptyNodesSubtrees::empty_subtrees_64()[depth..depth + Self::TIER_DEPTH as usize + 1];

        SimpleSmt::new(Self::TIER_DEPTH)
            .map(|smt| smt.with_empty_subtrees(empty_subtrees.iter().copied()))
    }

    /// Get a subtree with the provided root from the storage or generate a new subtree.
    fn get_tree(&self, root: &NodeIndex) -> Result<SimpleSmt, MerkleError> {
        self.storage
            .get_tree(root)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| Self::generate_simple_smt(root.depth()))
    }

    /// Returns a tuple with the sub-tree root index, and the relative index on that sub-tree
    fn get_subtree_index(index: &NodeIndex) -> (NodeIndex, NodeIndex) {
        // compute the sub-tree root index
        let depth = index.depth() / Self::TIER_DEPTH;
        let depth = depth.saturating_sub(1) * Self::TIER_DEPTH;
        let tiers = index.depth() - depth;
        let value = index.value() >> tiers;
        let subtree_root = NodeIndex::new(depth, value);

        // compute the relative index
        let skipped = 1 << (depth + Self::TIER_DEPTH);
        let skipped = value * skipped;
        let value = index.value() - skipped;
        let mut relative_index = NodeIndex::new(Self::TIER_DEPTH, value);

        // move up until internal node
        while relative_index.depth() != index.depth() - subtree_root.depth() {
            relative_index.move_up();
        }
        (subtree_root, relative_index)
    }

    /// Returns `true` if the index doesn't contain any leaf
    fn is_leaf(&self, index: &NodeIndex) -> bool {
        if index.depth() == Self::MAX_DEPTH {
            debug_assert_ne!(
                self.storage
                    .get_bottom_leaves(index.value())
                    .map(|l| l.len())
                    .unwrap_or(1),
                0,
                "bottom leaves should either be absent or contain leaves"
            );
            self.storage.get_bottom_leaves(index.value()).is_some()
        } else {
            self.storage.is_leaf(index)
        }
    }

    /// Computes a node index from a key/depth pair.
    const fn index_from_key(key: &CanonicalWord, depth: u8) -> NodeIndex {
        let value = key.last_limb() >> (64 - depth);
        NodeIndex::new(depth, value)
    }

    /// Computes the node for a bottom leaves set.
    fn hash_bottom_leaves<I, K, V>(leaves: I) -> RpoDigest
    where
        K: Borrow<CanonicalWord>,
        V: Borrow<Word>,
        I: IntoIterator<Item = (K, V)>,
    {
        let inputs: Vec<_> = leaves
            .into_iter()
            .map(|(k, v)| (Word::from(k.borrow()), *v.borrow()))
            .flat_map(|(k, v)| k.into_iter().chain(v.into_iter()))
            .collect();
        // TODO need a hash elements in domain so we can hash the batch of leaves.
        Rpo256::hash_elements(&inputs)
    }

    /// Computes the node for an upper leaf.
    fn hash_upper_leaf(key: RpoDigest, value: RpoDigest, depth: u8) -> RpoDigest {
        let domain = Felt::new(depth as u64);
        Rpo256::merge_in_domain(&[key, value], domain)
    }

    /// Update the leaf path from index to root.
    fn update_leaf_path(
        &mut self,
        mut index: NodeIndex,
        key: CanonicalWord,
    ) -> Result<&Word, MerkleError> {
        debug_assert_eq!(
            index.depth() % Self::TIER_DEPTH,
            0,
            "this method is allowed only for tier levels"
        );

        let value = self
            .storage
            .get_leaf_value(&key)
            .copied()
            .ok_or_else(|| MerkleError::NodeNotInSet(index.value()))?;

        // update storage leaf data
        self.storage.replace_leaf_key(key, index);
        if index.depth() == Self::MAX_DEPTH {
            self.storage.replace_bottom_leaf(index.value(), key, value);
        }

        let mut node = if index.depth() == Self::MAX_DEPTH {
            self.storage
                .get_bottom_leaves(index.value())
                .cloned()
                .map(Self::hash_bottom_leaves)
                .unwrap_or_else(|| EmptyNodesSubtrees::get_node_64(Self::MAX_DEPTH))
                .into()
        } else {
            Self::hash_upper_leaf(key.into(), value.into(), index.depth()).into()
        };

        // fetch each sub-tree and update their path to their relative root.
        while index.depth() > 0 {
            let (subtree, relative) = Self::get_subtree_index(&index);
            let mut tree = self
                .storage
                .take_tree(&subtree)
                .map(Ok)
                .unwrap_or_else(|| Self::generate_simple_smt(subtree.depth()))?;
            tree.insert_leaf(relative.value(), node)?;
            node = tree.root();
            self.storage.replace_tree(subtree, tree);
            index.move_up_by(Self::TIER_DEPTH);
        }

        self.root = node;
        Ok(&self.root)
    }
}
