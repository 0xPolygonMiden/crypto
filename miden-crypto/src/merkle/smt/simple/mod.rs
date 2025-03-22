use alloc::{collections::BTreeSet, vec::Vec};

use super::{
    super::ValuePath, EMPTY_WORD, EmptySubtreeRoots, InnerNode, InnerNodeInfo, InnerNodes,
    LeafIndex, MerkleError, MerklePath, MutationSet, NodeIndex, RpoDigest, SMT_MAX_DEPTH,
    SMT_MIN_DEPTH, SparseMerkleTree, Word,
};
use crate::merkle::{SparseMerklePath, sparse_path::SparseValuePath};

#[cfg(test)]
mod tests;

// SPARSE MERKLE TREE
// ================================================================================================

type Leaves = super::Leaves<Word>;

/// A sparse Merkle tree with 64-bit keys and 4-element leaf values, without compaction.
///
/// The root of the tree is recomputed on each new leaf update.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SimpleSmt<const DEPTH: u8> {
    root: RpoDigest,
    inner_nodes: InnerNodes,
    leaves: Leaves,
}

impl<const DEPTH: u8> SimpleSmt<DEPTH> {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The default value used to compute the hash of empty leaves
    pub const EMPTY_VALUE: Word = <Self as SparseMerkleTree<DEPTH>>::EMPTY_VALUE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [SimpleSmt].
    ///
    /// All leaves in the returned tree are set to [ZERO; 4].
    ///
    /// # Errors
    /// Returns an error if DEPTH is 0 or is greater than 64.
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
            inner_nodes: Default::default(),
            leaves: Default::default(),
        })
    }

    /// Returns a new [SimpleSmt] instantiated with leaves set as specified by the provided entries.
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
        let max_num_entries = 2_usize.pow(DEPTH.min(63).into());

        // This being a sparse data structure, the EMPTY_WORD is not assigned to the `BTreeMap`, so
        // entries with the empty value need additional tracking.
        let mut key_set_to_zero = BTreeSet::new();

        for (idx, (key, value)) in entries.into_iter().enumerate() {
            if idx >= max_num_entries {
                return Err(MerkleError::TooManyEntries(max_num_entries));
            }

            let old_value = tree.insert(LeafIndex::<DEPTH>::new(key)?, value);

            if old_value != Self::EMPTY_VALUE || key_set_to_zero.contains(&key) {
                return Err(MerkleError::DuplicateValuesForIndex(key));
            }

            if value == Self::EMPTY_VALUE {
                key_set_to_zero.insert(key);
            };
        }
        Ok(tree)
    }

    /// Returns a new [`SimpleSmt`] instantiated from already computed leaves and nodes.
    ///
    /// This function performs minimal consistency checking. It is the caller's responsibility to
    /// ensure the passed arguments are correct and consistent with each other.
    ///
    /// # Panics
    /// With debug assertions on, this function panics if `root` does not match the root node in
    /// `inner_nodes`.
    pub fn from_raw_parts(inner_nodes: InnerNodes, leaves: Leaves, root: RpoDigest) -> Self {
        // Our particular implementation of `from_raw_parts()` never returns `Err`.
        <Self as SparseMerkleTree<DEPTH>>::from_raw_parts(inner_nodes, leaves, root).unwrap()
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

    /// Returns the depth of the tree
    pub const fn depth(&self) -> u8 {
        DEPTH
    }

    /// Returns the root of the tree
    pub fn root(&self) -> RpoDigest {
        <Self as SparseMerkleTree<DEPTH>>::root(self)
    }

    /// Returns the number of non-empty leaves in this tree.
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Returns the leaf at the specified index.
    pub fn get_leaf(&self, key: &LeafIndex<DEPTH>) -> Word {
        <Self as SparseMerkleTree<DEPTH>>::get_leaf(self, key)
    }

    /// Returns a node at the specified index.
    ///
    /// # Errors
    /// Returns an error if the specified index has depth set to 0 or the depth is greater than
    /// the depth of this Merkle tree.
    pub fn get_node(&self, index: NodeIndex) -> Result<RpoDigest, MerkleError> {
        if index.is_root() {
            Err(MerkleError::DepthTooSmall(index.depth()))
        } else if index.depth() > DEPTH {
            Err(MerkleError::DepthTooBig(index.depth() as u64))
        } else if index.depth() == DEPTH {
            let leaf = self.get_leaf(&LeafIndex::<DEPTH>::try_from(index)?);

            Ok(leaf.into())
        } else {
            Ok(self.get_inner_node(index).hash())
        }
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &LeafIndex<DEPTH>) -> ValuePath {
        <Self as SparseMerkleTree<DEPTH>>::open(self, key)
    }

    /// Returns a path (but not an opening) to the leaf associated with `key`.
    ///
    /// Unlike [`SimpleSmt::open()`], this returns a [SparseValuePath] which has a more efficient
    /// memory representation optimized for paths containing empty nodes. See [SparseMerklePath]
    /// for more information.
    pub fn get_path(&self, key: &LeafIndex<DEPTH>) -> SparseValuePath {
        let value: RpoDigest = self.get_value(key).into();

        // This is a partial re-implementation of `SparseMerklePath::from_sized_iter()`, which
        // constructs in place instead of cloning and immediately dropping the entire vec returned
        // by `self.open()`.

        let mut nodes: Vec<RpoDigest> = Default::default();
        let mut index = NodeIndex::from(*key);
        let mut empty_nodes: u64 = 0;

        for _ in 0..DEPTH {
            let is_right = index.is_value_odd();
            index.move_up();

            match self.inner_nodes.get(&index) {
                Some(InnerNode { left, right }) => {
                    let value = if is_right { left } else { right };
                    nodes.push(*value);
                },
                None => empty_nodes |= u64::checked_shl(1, index.depth().into()).unwrap(),
            }
        }

        let path = SparseMerklePath::from_raw_parts(empty_nodes, nodes);

        SparseValuePath { value, path }
    }

    /// Returns a boolean value indicating whether the SMT is empty.
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.leaves.is_empty(), self.root == Self::EMPTY_ROOT);
        self.root == Self::EMPTY_ROOT
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [SimpleSmt].
    pub fn leaves(&self) -> impl Iterator<Item = (u64, &Word)> {
        self.leaves.iter().map(|(i, w)| (*i, w))
    }

    /// Returns an iterator over the inner nodes of this [SimpleSmt].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.inner_nodes.values().map(|e| InnerNodeInfo {
            value: e.hash(),
            left: e.left,
            right: e.right,
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`EMPTY_WORD`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    pub fn insert(&mut self, key: LeafIndex<DEPTH>, value: Word) -> Word {
        <Self as SparseMerkleTree<DEPTH>>::insert(self, key, value)
    }

    /// Computes what changes are necessary to insert the specified key-value pairs into this
    /// Merkle tree, allowing for validation before applying those changes.
    ///
    /// This method returns a [`MutationSet`], which contains all the information for inserting
    /// `kv_pairs` into this Merkle tree already calculated, including the new root hash, which can
    /// be queried with [`MutationSet::root()`]. Once a mutation set is returned,
    /// [`SimpleSmt::apply_mutations()`] can be called in order to commit these changes to the
    /// Merkle tree, or [`drop()`] to discard them.
    ///
    /// # Example
    /// ```
    /// # use miden_crypto::{hash::rpo::RpoDigest, Felt, Word};
    /// # use miden_crypto::merkle::{LeafIndex, SimpleSmt, EmptySubtreeRoots, SMT_DEPTH};
    /// let mut smt: SimpleSmt<3> = SimpleSmt::new().unwrap();
    /// let pair = (LeafIndex::default(), Word::default());
    /// let mutations = smt.compute_mutations(vec![pair]);
    /// assert_eq!(mutations.root(), *EmptySubtreeRoots::entry(3, 0));
    /// smt.apply_mutations(mutations);
    /// assert_eq!(smt.root(), *EmptySubtreeRoots::entry(3, 0));
    /// ```
    pub fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (LeafIndex<DEPTH>, Word)>,
    ) -> MutationSet<DEPTH, LeafIndex<DEPTH>, Word> {
        <Self as SparseMerkleTree<DEPTH>>::compute_mutations(self, kv_pairs)
    }

    /// Applies the prospective mutations computed with [`SimpleSmt::compute_mutations()`] to this
    /// tree.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`alloc::vec::Vec`]. The first item is the
    /// root hash the `mutations` were computed against, and the second item is the actual
    /// current root of this tree.
    pub fn apply_mutations(
        &mut self,
        mutations: MutationSet<DEPTH, LeafIndex<DEPTH>, Word>,
    ) -> Result<(), MerkleError> {
        <Self as SparseMerkleTree<DEPTH>>::apply_mutations(self, mutations)
    }

    /// Applies the prospective mutations computed with [`SimpleSmt::compute_mutations()`] to
    /// this tree and returns the reverse mutation set.
    ///
    /// Applying the reverse mutation sets to the updated tree will revert the changes.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`alloc::vec::Vec`]. The first item is the
    /// root hash the `mutations` were computed against, and the second item is the actual
    /// current root of this tree.
    pub fn apply_mutations_with_reversion(
        &mut self,
        mutations: MutationSet<DEPTH, LeafIndex<DEPTH>, Word>,
    ) -> Result<MutationSet<DEPTH, LeafIndex<DEPTH>, Word>, MerkleError> {
        <Self as SparseMerkleTree<DEPTH>>::apply_mutations_with_reversion(self, mutations)
    }

    /// Inserts a subtree at the specified index. The depth at which the subtree is inserted is
    /// computed as `DEPTH - SUBTREE_DEPTH`.
    ///
    /// Returns the new root.
    pub fn set_subtree<const SUBTREE_DEPTH: u8>(
        &mut self,
        subtree_insertion_index: u64,
        subtree: SimpleSmt<SUBTREE_DEPTH>,
    ) -> Result<RpoDigest, MerkleError> {
        if SUBTREE_DEPTH > DEPTH {
            return Err(MerkleError::SubtreeDepthExceedsDepth {
                subtree_depth: SUBTREE_DEPTH,
                tree_depth: DEPTH,
            });
        }

        // Verify that `subtree_insertion_index` is valid.
        let subtree_root_insertion_depth = DEPTH - SUBTREE_DEPTH;
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
        let leaf_index_shift: u64 = subtree_insertion_index * 2_u64.pow(SUBTREE_DEPTH.into());
        for (subtree_leaf_idx, leaf_value) in subtree.leaves() {
            let new_leaf_idx = leaf_index_shift + subtree_leaf_idx;
            debug_assert!(new_leaf_idx < 2_u64.pow(DEPTH.into()));

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
    type Opening = ValuePath;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;
    const EMPTY_ROOT: RpoDigest = *EmptySubtreeRoots::entry(DEPTH, 0);

    fn from_raw_parts(
        inner_nodes: InnerNodes,
        leaves: Leaves,
        root: RpoDigest,
    ) -> Result<Self, MerkleError> {
        if cfg!(debug_assertions) {
            let root_node = inner_nodes.get(&NodeIndex::root()).unwrap();
            assert_eq!(root_node.hash(), root);
        }

        Ok(Self { root, inner_nodes, leaves })
    }

    fn root(&self) -> RpoDigest {
        self.root
    }

    fn set_root(&mut self, root: RpoDigest) {
        self.root = root;
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        self.inner_nodes
            .get(&index)
            .cloned()
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        self.inner_nodes.insert(index, inner_node)
    }

    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        self.inner_nodes.remove(&index)
    }

    fn insert_value(&mut self, key: LeafIndex<DEPTH>, value: Word) -> Option<Word> {
        if value == Self::EMPTY_VALUE {
            self.leaves.remove(&key.value())
        } else {
            self.leaves.insert(key.value(), value)
        }
    }

    fn get_value(&self, key: &LeafIndex<DEPTH>) -> Word {
        self.get_leaf(key)
    }

    fn get_leaf(&self, key: &LeafIndex<DEPTH>) -> Word {
        let leaf_pos = key.value();
        match self.leaves.get(&leaf_pos) {
            Some(word) => *word,
            None => Self::EMPTY_VALUE,
        }
    }

    fn hash_leaf(leaf: &Word) -> RpoDigest {
        // `SimpleSmt` takes the leaf value itself as the hash
        leaf.into()
    }

    fn construct_prospective_leaf(
        &self,
        _existing_leaf: Word,
        _key: &LeafIndex<DEPTH>,
        value: &Word,
    ) -> Word {
        *value
    }

    fn key_to_leaf_index(key: &LeafIndex<DEPTH>) -> LeafIndex<DEPTH> {
        *key
    }

    fn path_and_leaf_to_opening(path: MerklePath, leaf: Word) -> ValuePath {
        (path, leaf).into()
    }
}
