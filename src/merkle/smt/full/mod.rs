#[cfg(feature = "async")]
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString,
    vec::Vec,
};
#[cfg(feature = "async")]
use tokio::task::JoinSet;

#[cfg(feature = "async")]
use super::NodeMutation;
use super::{
    EmptySubtreeRoots, Felt, InnerNode, InnerNodeInfo, LeafIndex, MerkleError, MerklePath,
    MutationSet, NodeIndex, Rpo256, RpoDigest, SparseMerkleTree, Word, EMPTY_WORD,
};
#[cfg(feature = "async")]
use crate::merkle::index::SubtreeIndex;

mod error;
pub use error::{SmtLeafError, SmtProofError};

mod leaf;
pub use leaf::SmtLeaf;

mod proof;
pub use proof::SmtProof;
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

pub const SMT_DEPTH: u8 = 64;

// SMT
// ================================================================================================

/// Sparse Merkle tree mapping 256-bit keys to 256-bit values. Both keys and values are represented
/// by 4 field elements.
///
/// All leaves sit at depth 64. The most significant element of the key is used to identify the leaf
/// to which the key maps.
///
/// A leaf is either empty, or holds one or more key-value pairs. An empty leaf hashes to the empty
/// word. Otherwise, a leaf hashes to the hash of its key-value pairs, ordered by key first, value
/// second.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Smt {
    root: RpoDigest,

    #[cfg(not(feature = "async"))]
    leaves: BTreeMap<u64, SmtLeaf>,
    #[cfg(feature = "async")]
    leaves: Arc<BTreeMap<u64, SmtLeaf>>,

    #[cfg(not(feature = "async"))]
    inner_nodes: BTreeMap<NodeIndex, InnerNode>,
    #[cfg(feature = "async")]
    inner_nodes: Arc<BTreeMap<NodeIndex, InnerNode>>,
}

impl Smt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// The default value used to compute the hash of empty leaves
    pub const EMPTY_VALUE: Word = <Self as SparseMerkleTree<SMT_DEPTH>>::EMPTY_VALUE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [Smt].
    ///
    /// All leaves in the returned tree are set to [Self::EMPTY_VALUE].
    pub fn new() -> Self {
        let root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

        Self {
            root,
            leaves: Default::default(),
            inner_nodes: Default::default(),
        }
    }

    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    pub fn with_entries(
        entries: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> Result<Self, MerkleError> {
        // create an empty tree
        let mut tree = Self::new();

        // This being a sparse data structure, the EMPTY_WORD is not assigned to the `BTreeMap`, so
        // entries with the empty value need additional tracking.
        let mut key_set_to_zero = BTreeSet::new();

        for (key, value) in entries {
            let old_value = tree.insert(key, value);

            if old_value != EMPTY_WORD || key_set_to_zero.contains(&key) {
                return Err(MerkleError::DuplicateValuesForIndex(
                    LeafIndex::<SMT_DEPTH>::from(key).value(),
                ));
            }

            if value == EMPTY_WORD {
                key_set_to_zero.insert(key);
            };
        }
        Ok(tree)
    }

    #[cfg(feature = "async")]
    pub fn get_leaves(&self) -> Arc<BTreeMap<u64, SmtLeaf>> {
        Arc::clone(&self.leaves)
    }

    #[cfg(feature = "async")]
    pub async fn compute_mutations_parallel(
        &self,
        kv_pairs: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> MutationSet<SMT_DEPTH, RpoDigest, Word> {
        <Self as super::ParallelSparseMerkleTree<SMT_DEPTH>>::compute_mutations_parallel(
            self, kv_pairs,
        )
        .await
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of the tree
    pub const fn depth(&self) -> u8 {
        SMT_DEPTH
    }

    /// Returns the root of the tree
    pub fn root(&self) -> RpoDigest {
        <Self as SparseMerkleTree<SMT_DEPTH>>::root(self)
    }

    /// Returns the leaf to which `key` maps
    pub fn get_leaf(&self, key: &RpoDigest) -> SmtLeaf {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_leaf(self, key)
    }

    /// Returns the value associated with `key`
    pub fn get_value(&self, key: &RpoDigest) -> Word {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_value(self, key)
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &RpoDigest) -> SmtProof {
        <Self as SparseMerkleTree<SMT_DEPTH>>::open(self, key)
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [Smt].
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.leaves
            .iter()
            .map(|(leaf_index, leaf)| (LeafIndex::new_max_depth(*leaf_index), leaf))
    }

    /// Returns an iterator over the key-value pairs of this [Smt].
    pub fn entries(&self) -> impl Iterator<Item = &(RpoDigest, Word)> {
        self.leaves().flat_map(|(_, leaf)| leaf.entries())
    }

    /// Returns an iterator over the inner nodes of this [Smt].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.inner_nodes.values().map(|e| InnerNodeInfo {
            value: e.hash(),
            left: e.left,
            right: e.right,
        })
    }

    /// Gets a mutable reference to this structure's inner node mapping.
    ///
    /// # Panics
    /// This will panic if we have violated our own invariants and try to mutate these nodes while
    /// Self::compute_mutations_parallel() is still running.
    fn inner_nodes_mut(&mut self) -> &mut BTreeMap<NodeIndex, InnerNode> {
        #[cfg(feature = "async")]
        {
            Arc::get_mut(&mut self.inner_nodes).unwrap()
        }

        #[cfg(not(feature = "async"))]
        {
            &mut self.inner_nodes
        }
    }

    /// Gets a mutable reference to this structure's inner leaf mapping.
    ///
    /// # Panics
    /// This will panic if we have violated our own invariants and try to mutate these nodes while
    /// Self::compute_mutations_parallel() is still running.
    fn leaves_mut(&mut self) -> &mut BTreeMap<u64, SmtLeaf> {
        #[cfg(feature = "async")]
        {
            Arc::get_mut(&mut self.leaves).unwrap()
        }

        #[cfg(not(feature = "async"))]
        {
            &mut self.leaves
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    pub fn insert(&mut self, key: RpoDigest, value: Word) -> Word {
        <Self as SparseMerkleTree<SMT_DEPTH>>::insert(self, key, value)
    }

    /// Computes what changes are necessary to insert the specified key-value pairs into this Merkle
    /// tree, allowing for validation before applying those changes.
    ///
    /// This method returns a [`MutationSet`], which contains all the information for inserting
    /// `kv_pairs` into this Merkle tree already calculated, including the new root hash, which can
    /// be queried with [`MutationSet::root()`]. Once a mutation set is returned,
    /// [`Smt::apply_mutations()`] can be called in order to commit these changes to the Merkle
    /// tree, or [`drop()`] to discard them.
    ///
    /// # Example
    /// ```
    /// # use miden_crypto::{hash::rpo::RpoDigest, Felt, Word};
    /// # use miden_crypto::merkle::{Smt, EmptySubtreeRoots, SMT_DEPTH};
    /// let mut smt = Smt::new();
    /// let pair = (RpoDigest::default(), Word::default());
    /// let mutations = smt.compute_mutations(vec![pair]);
    /// assert_eq!(mutations.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// smt.apply_mutations(mutations);
    /// assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// ```
    pub fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> MutationSet<SMT_DEPTH, RpoDigest, Word> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::compute_mutations(self, kv_pairs)
    }

    /// Apply the prospective mutations computed with [`Smt::compute_mutations()`] to this tree.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, RpoDigest, Word>,
    ) -> Result<(), MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::apply_mutations(self, mutations)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Inserts `value` at leaf index pointed to by `key`. `value` is guaranteed to not be the empty
    /// value, such that this is indeed an insertion.
    fn perform_insert(&mut self, key: RpoDigest, value: Word) -> Option<Word> {
        debug_assert_ne!(value, Self::EMPTY_VALUE);

        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        let leaves = self.leaves_mut();

        match leaves.get_mut(&leaf_index.value()) {
            Some(leaf) => leaf.insert(key, value),
            None => {
                leaves.insert(leaf_index.value(), SmtLeaf::Single((key, value)));

                None
            },
        }
    }

    /// Removes key-value pair at leaf index pointed to by `key` if it exists.
    fn perform_remove(&mut self, key: RpoDigest) -> Option<Word> {
        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        let leaves = self.leaves_mut();

        if let Some(leaf) = leaves.get_mut(&leaf_index.value()) {
            let (old_value, is_empty) = leaf.remove(key);
            if is_empty {
                leaves.remove(&leaf_index.value());
            }
            old_value
        } else {
            // there's nothing stored at the leaf; nothing to update
            None
        }
    }

    fn construct_prospective_leaf(
        mut existing_leaf: SmtLeaf,
        key: &RpoDigest,
        value: &Word,
    ) -> SmtLeaf {
        debug_assert_eq!(existing_leaf.index(), Self::key_to_leaf_index(key));

        match existing_leaf {
            SmtLeaf::Empty(_) => SmtLeaf::new_single(*key, *value),
            _ => {
                if *value != EMPTY_WORD {
                    existing_leaf.insert(*key, *value);
                } else {
                    existing_leaf.remove(*key);
                }

                existing_leaf
            },
        }
    }
}

impl SparseMerkleTree<SMT_DEPTH> for Smt {
    type Key = RpoDigest;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = SmtProof;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;

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
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) {
        self.inner_nodes_mut().insert(index, inner_node);
    }

    fn remove_inner_node(&mut self, index: NodeIndex) {
        let _ = self.inner_nodes_mut().remove(&index);
    }

    fn insert_value(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value> {
        // inserting an `EMPTY_VALUE` is equivalent to removing any value associated with `key`
        if value != Self::EMPTY_VALUE {
            self.perform_insert(key, value)
        } else {
            self.perform_remove(key)
        }
    }

    fn get_value(&self, key: &Self::Key) -> Self::Value {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.get_value(key).unwrap_or_default(),
            None => EMPTY_WORD,
        }
    }

    fn get_leaf(&self, key: &RpoDigest) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.clone(),
            None => SmtLeaf::new_empty(key.into()),
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest {
        leaf.hash()
    }

    fn construct_prospective_leaf(
        &self,
        existing_leaf: SmtLeaf,
        key: &RpoDigest,
        value: &Word,
    ) -> SmtLeaf {
        Smt::construct_prospective_leaf(existing_leaf, key, value)
    }

    fn key_to_leaf_index(key: &RpoDigest) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_int())
    }

    fn path_and_leaf_to_opening(path: MerklePath, leaf: SmtLeaf) -> SmtProof {
        SmtProof::new_unchecked(path, leaf)
    }
}

#[cfg(feature = "async")]
impl super::ParallelSparseMerkleTree<SMT_DEPTH> for Smt {
    // Helpers required only for the parallel version of the SMT trait.
    fn get_inner_nodes(&self) -> Arc<BTreeMap<NodeIndex, InnerNode>> {
        Arc::clone(&self.inner_nodes)
    }

    fn get_leaves(&self) -> Arc<BTreeMap<u64, SmtLeaf>> {
        Arc::clone(&self.leaves)
    }

    async fn compute_mutations_parallel<I>(
        &self,
        kv_pairs: I,
    ) -> MutationSet<SMT_DEPTH, RpoDigest, Word>
    where
        I: IntoIterator<Item = (RpoDigest, Word)>,
    {
        use std::time::Instant;

        const SUBTREE_INTERVAL: u8 = 8;

        // FIXME: check for duplicates and return MerkleError.
        let kv_pairs = Arc::new(BTreeMap::from_iter(kv_pairs));

        // The first subtrees we calculate, which include our new leaves.
        let mut subtrees: HashSet<NodeIndex> = kv_pairs
            .keys()
            .map(|key| {
                let index_for_key = NodeIndex::from(Smt::key_to_leaf_index(key));
                index_for_key.parent_n(SUBTREE_INTERVAL)
            })
            .collect();

        // Node mutations across all tasks will be collected here.
        // Every time we collect tasks we store all the new known node mutations and their hashes
        // (so we don't have to recompute them every time we need them).
        let mut node_mutations: Arc<HashMap<NodeIndex, (RpoDigest, NodeMutation)>> =
            Default::default();
        // Any leaf hashes done by tasks will be collected here, so hopefully we only hash each leaf
        // once.
        let mut cached_leaf_hashes: Arc<HashMap<LeafIndex<SMT_DEPTH>, RpoDigest>> =
            Default::default();

        for subtree_depth in (0..SMT_DEPTH).step_by(SUBTREE_INTERVAL.into()).rev() {
            let now = Instant::now();
            let mut tasks = JoinSet::new();

            for subtree in subtrees.iter().copied() {
                debug_assert_eq!(subtree.depth(), subtree_depth);
                let mut state = NodeSubtreeState::<SMT_DEPTH>::with_smt(
                    &self,
                    Arc::clone(&node_mutations),
                    Arc::clone(&kv_pairs),
                    SubtreeIndex::new(subtree, SUBTREE_INTERVAL as u8),
                );
                // The "double spawn" here is necessary to allow tokio to run these tasks in
                // parallel.
                tasks.spawn(tokio::spawn(async move {
                    let hash = state.get_or_make_hash(subtree);
                    (subtree, hash, state.into_results())
                }));
            }

            let task_results = tasks.join_all().await;
            let elapsed = now.elapsed();
            std::eprintln!(
                "joined {} tasks for depth {} in {:.3} milliseconds",
                task_results.len(),
                subtree_depth,
                elapsed.as_secs_f64() * 1000.0,
            );

            for result in task_results {
                // FIXME: .expect() error message?
                let result = result.unwrap();
                let (subtree, hash, state) = result;
                let NodeSubtreeResults {
                    new_mutations,
                    cached_leaf_hashes: new_leaf_hashes,
                } = state;

                Arc::get_mut(&mut node_mutations).unwrap().extend(new_mutations);
                Arc::get_mut(&mut cached_leaf_hashes).unwrap().extend(new_leaf_hashes);
                // Make sure the final hash we calculated is in the new mutations.
                assert_eq!(
                    node_mutations.get(&subtree).unwrap().0,
                    hash,
                    "Stored and returned hashes for subtree '{subtree:?}' differ",
                );
            }

            // And advance our subtrees, unless we just did the root depth.
            if subtree_depth == 0 {
                continue;
            }

            let subtree_count_before_advance = subtrees.len();
            subtrees =
                subtrees.into_iter().map(|subtree| subtree.parent_n(SUBTREE_INTERVAL)).collect();
            // FIXME: remove.
            assert!(subtrees.len() <= subtree_count_before_advance);
        }

        let root = NodeIndex::root();
        let new_root = node_mutations.get(&root).unwrap().0;

        MutationSet {
            old_root: self.root(),
            //node_mutations: Arc::into_inner(node_mutations).unwrap().into_iter().collect(),
            node_mutations: Arc::into_inner(node_mutations)
                .unwrap()
                .into_iter()
                .map(|(key, (_hash, node))| (key, node))
                .collect(),
            new_pairs: Arc::into_inner(kv_pairs).unwrap(),
            new_root,
        }
    }
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "async")]
pub(crate) struct NodeSubtreeState<const DEPTH: u8> {
    inner_nodes: Arc<BTreeMap<NodeIndex, InnerNode>>,
    leaves: Arc<BTreeMap<u64, SmtLeaf>>,
    // This field has invariants!
    dirtied_indices: HashMap<NodeIndex, bool>,
    existing_mutations: Arc<HashMap<NodeIndex, (RpoDigest, NodeMutation)>>,
    new_mutations: HashMap<NodeIndex, (RpoDigest, NodeMutation)>,
    new_pairs: Arc<BTreeMap<RpoDigest, Word>>,
    cached_leaf_hashes: HashMap<LeafIndex<SMT_DEPTH>, RpoDigest>,
    indentation: u8,
    subtree: SubtreeIndex,
}

#[cfg(feature = "async")]
impl<const DEPTH: u8> NodeSubtreeState<DEPTH> {
    pub(crate) fn new(
        inner_nodes: Arc<BTreeMap<NodeIndex, InnerNode>>,
        existing_mutations: Arc<HashMap<NodeIndex, (RpoDigest, NodeMutation)>>,
        leaves: Arc<BTreeMap<u64, SmtLeaf>>,
        new_pairs: Arc<BTreeMap<RpoDigest, Word>>,
        subtree: SubtreeIndex,
    ) -> Self {
        Self {
            inner_nodes,
            leaves,
            dirtied_indices: Default::default(),
            new_mutations: Default::default(),
            existing_mutations,
            new_pairs,
            cached_leaf_hashes: Default::default(),
            indentation: 0,
            subtree,
        }
    }

    pub(crate) fn with_smt(
        smt: &Smt,
        existing_mutations: Arc<HashMap<NodeIndex, (RpoDigest, NodeMutation)>>,
        new_pairs: Arc<BTreeMap<RpoDigest, Word>>,
        subtree: SubtreeIndex,
    ) -> Self {
        Self::new(
            Arc::clone(&smt.inner_nodes),
            existing_mutations,
            Arc::clone(&smt.leaves),
            new_pairs,
            subtree,
        )
    }

    #[inline(never)] // XXX: for profiling.
    pub(crate) fn is_index_dirty(&mut self, index_to_check: NodeIndex) -> bool {
        if index_to_check == self.subtree.root {
            return true;
        }
        if let Some(cached) = self.dirtied_indices.get(&index_to_check) {
            return *cached;
        }
        let is_dirty = self
            .existing_mutations
            .iter()
            .map(|(index, _)| *index)
            .chain(self.new_pairs.iter().map(|(key, _v)| Smt::key_to_leaf_index(key).index))
            .filter(|&dirtied_index| index_to_check.contains(dirtied_index))
            .next()
            .is_some();
        self.dirtied_indices.insert(index_to_check, is_dirty);
        is_dirty
    }

    /// Does NOT check `new_mutations`.
    #[inline(never)] // XXX: for profiling.
    pub(crate) fn get_clean_hash(&self, index: NodeIndex) -> Option<RpoDigest> {
        self.existing_mutations
            .get(&index)
            .map(|(hash, _)| *hash)
            .or_else(|| self.inner_nodes.get(&index).map(|inner_node| InnerNode::hash(&inner_node)))
    }

    #[inline(never)] // XXX: for profiling.
    pub(crate) fn get_effective_leaf(&self, index: LeafIndex<SMT_DEPTH>) -> SmtLeaf {
        let pairs_at_index = self
            .new_pairs
            .iter()
            .filter(|&(new_key, _)| Smt::key_to_leaf_index(new_key) == index);

        let existing_leaf = self
            .leaves
            .get(&index.index.value())
            .cloned()
            .unwrap_or_else(|| SmtLeaf::new_empty(index));

        pairs_at_index.fold(existing_leaf, |acc, (k, v)| {
            let existing_leaf = acc.clone();
            Smt::construct_prospective_leaf(existing_leaf, k, v)
        })
    }

    /// Retrieve a cached hash, or recursively compute it.
    #[inline(never)] // XXX: for profiling.
    pub fn get_or_make_hash(&mut self, index: NodeIndex) -> RpoDigest {
        use NodeMutation::*;

        // If this is a leaf, then only do leaf stuff.
        if index.depth() == SMT_DEPTH {
            let index = LeafIndex::new(index.value()).unwrap();
            return match self.cached_leaf_hashes.get(&index) {
                Some(cached_hash) => cached_hash.clone(),
                None => {
                    let leaf = self.get_effective_leaf(index);
                    let hash = Smt::hash_leaf(&leaf);
                    self.cached_leaf_hashes.insert(index, hash);
                    hash
                },
            };
        }

        // If we already computed this one earlier as a mutation, just return it.
        if let Some((hash, _)) = self.new_mutations.get(&index) {
            return *hash;
        }

        // Otherwise, we need to know if this node is one of the nodes we're in the process of
        // recomputing, or if we can safely use the node already in the Merkle tree.
        if !self.is_index_dirty(index) {
            return self
                .get_clean_hash(index)
                .unwrap_or_else(|| *EmptySubtreeRoots::entry(SMT_DEPTH, index.depth()));
        }

        // If we got here, then we have to make, rather than get, this hash.
        // Make sure we mark this index as now dirty.
        self.dirtied_indices.insert(index, true);

        // Recurse for the left and right sides.
        let left = self.get_or_make_hash(index.left_child());
        let right = self.get_or_make_hash(index.right_child());
        let node = InnerNode { left, right };
        let hash = node.hash();
        let &equivalent_empty_hash = EmptySubtreeRoots::entry(SMT_DEPTH, index.depth());
        let is_removal = hash == equivalent_empty_hash;
        let new_entry = if is_removal { Removal } else { Addition(node) };

        self.new_mutations.insert(index, (hash, new_entry));

        hash
    }

    fn into_results(self) -> NodeSubtreeResults {
        NodeSubtreeResults {
            new_mutations: self.new_mutations,
            cached_leaf_hashes: self.cached_leaf_hashes,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg(feature = "async")]
pub(crate) struct NodeSubtreeResults {
    pub(crate) new_mutations: HashMap<NodeIndex, (RpoDigest, NodeMutation)>,
    pub(crate) cached_leaf_hashes: HashMap<LeafIndex<SMT_DEPTH>, RpoDigest>,
}

// CONVERSIONS
// ================================================================================================

impl From<Word> for LeafIndex<SMT_DEPTH> {
    fn from(value: Word) -> Self {
        // We use the most significant `Felt` of a `Word` as the leaf index.
        Self::new_max_depth(value[3].as_int())
    }
}

impl From<RpoDigest> for LeafIndex<SMT_DEPTH> {
    fn from(value: RpoDigest) -> Self {
        Word::from(value).into()
    }
}

impl From<&RpoDigest> for LeafIndex<SMT_DEPTH> {
    fn from(value: &RpoDigest) -> Self {
        Word::from(value).into()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Smt {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write the number of filled leaves for this Smt
        target.write_usize(self.entries().count());

        // Write each (key, value) pair
        for (key, value) in self.entries() {
            target.write(key);
            target.write(value);
        }
    }
}

impl Deserializable for Smt {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read the number of filled leaves for this Smt
        let num_filled_leaves = source.read_usize()?;
        let mut entries = Vec::with_capacity(num_filled_leaves);

        for _ in 0..num_filled_leaves {
            let key = source.read()?;
            let value = source.read()?;
            entries.push((key, value));
        }

        Self::with_entries(entries)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

#[test]
fn test_smt_serialization_deserialization() {
    // Smt for default types (empty map)
    let smt_default = Smt::default();
    let bytes = smt_default.to_bytes();
    assert_eq!(smt_default, Smt::read_from_bytes(&bytes).unwrap());

    // Smt with values
    let smt_leaves_2: [(RpoDigest, Word); 2] = [
        (
            RpoDigest::new([Felt::new(101), Felt::new(102), Felt::new(103), Felt::new(104)]),
            [Felt::new(1_u64), Felt::new(2_u64), Felt::new(3_u64), Felt::new(4_u64)],
        ),
        (
            RpoDigest::new([Felt::new(105), Felt::new(106), Felt::new(107), Felt::new(108)]),
            [Felt::new(5_u64), Felt::new(6_u64), Felt::new(7_u64), Felt::new(8_u64)],
        ),
    ];
    let smt = Smt::with_entries(smt_leaves_2).unwrap();

    let bytes = smt.to_bytes();
    assert_eq!(smt, Smt::read_from_bytes(&bytes).unwrap());
}
