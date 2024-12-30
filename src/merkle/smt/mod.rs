use alloc::{collections::BTreeMap, vec::Vec};
use core::{hash::Hash, mem};

use num::Integer;
use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use super::{EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, NodeIndex};
use crate::{
    hash::rpo::{Rpo256, RpoDigest},
    Felt, Word, EMPTY_WORD,
};

mod full;
pub use full::{Smt, SmtLeaf, SmtLeafError, SmtProof, SmtProofError, SMT_DEPTH};

mod simple;
pub use simple::SimpleSmt;

// CONSTANTS
// ================================================================================================

/// Minimum supported depth.
pub const SMT_MIN_DEPTH: u8 = 1;

/// Maximum supported depth.
pub const SMT_MAX_DEPTH: u8 = 64;

// SPARSE MERKLE TREE
// ================================================================================================

/// A map whose keys are not guarantied to be ordered.
#[cfg(feature = "smt_hashmaps")]
type UnorderedMap<K, V> = hashbrown::HashMap<K, V>;
#[cfg(not(feature = "smt_hashmaps"))]
type UnorderedMap<K, V> = alloc::collections::BTreeMap<K, V>;
type InnerNodes = UnorderedMap<NodeIndex, InnerNode>;
type Leaves<T> = UnorderedMap<u64, T>;
type NodeMutations = UnorderedMap<NodeIndex, NodeMutation>;

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
/// must accommodate all keys that map to the same leaf.
///
/// [SparseMerkleTree] currently doesn't support optimizations that compress Merkle proofs.
pub(crate) trait SparseMerkleTree<const DEPTH: u8> {
    /// The type for a key
    type Key: Clone + Ord + Eq + Hash;
    /// The type for a value
    type Value: Clone + PartialEq;
    /// The type for a leaf
    type Leaf: Clone;
    /// The type for an opening (i.e. a "proof") of a leaf
    type Opening;

    /// The default value used to compute the hash of empty leaves
    const EMPTY_VALUE: Self::Value;

    /// The root of the empty tree with provided DEPTH
    const EMPTY_ROOT: RpoDigest;

    // PROVIDED METHODS
    // ---------------------------------------------------------------------------------------------

    /// Creates a new sparse Merkle tree from an existing set of key-value pairs, in parallel.
    #[cfg(feature = "concurrent")]
    fn with_entries_par(entries: Vec<(Self::Key, Self::Value)>) -> Result<Self, MerkleError>
    where
        Self: Sized,
    {
        let (inner_nodes, leaves) = Self::build_subtrees(entries);
        let root = inner_nodes.get(&NodeIndex::root()).unwrap().hash();
        Self::from_raw_parts(inner_nodes, leaves, root)
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    fn open(&self, key: &Self::Key) -> Self::Opening {
        let leaf = self.get_leaf(key);

        let mut index: NodeIndex = {
            let leaf_index: LeafIndex<DEPTH> = Self::key_to_leaf_index(key);
            leaf_index.into()
        };

        let merkle_path = {
            let mut path = Vec::with_capacity(index.depth() as usize);
            for _ in 0..index.depth() {
                let is_right = index.is_value_odd();
                index.move_up();
                let InnerNode { left, right } = self.get_inner_node(index);
                let value = if is_right { left } else { right };
                path.push(value);
            }

            MerklePath::new(path)
        };

        Self::path_and_leaf_to_opening(merkle_path, leaf)
    }

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Self::Value {
        let old_value = self.insert_value(key.clone(), value.clone()).unwrap_or(Self::EMPTY_VALUE);

        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return value;
        }

        let leaf = self.get_leaf(&key);
        let node_index = {
            let leaf_index: LeafIndex<DEPTH> = Self::key_to_leaf_index(&key);
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
        let mut node_hash = node_hash_at_index;
        for node_depth in (0..index.depth()).rev() {
            let is_right = index.is_value_odd();
            index.move_up();
            let InnerNode { left, right } = self.get_inner_node(index);
            let (left, right) = if is_right {
                (left, node_hash)
            } else {
                (node_hash, right)
            };
            node_hash = Rpo256::merge(&[left, right]);

            if node_hash == *EmptySubtreeRoots::entry(DEPTH, node_depth) {
                // If a subtree is empty, then can remove the inner node, since it's equal to the
                // default value
                self.remove_inner_node(index);
            } else {
                self.insert_inner_node(index, InnerNode { left, right });
            }
        }
        self.set_root(node_hash);
    }

    /// Computes what changes are necessary to insert the specified key-value pairs into this Merkle
    /// tree, allowing for validation before applying those changes.
    ///
    /// This method returns a [`MutationSet`], which contains all the information for inserting
    /// `kv_pairs` into this Merkle tree already calculated, including the new root hash, which can
    /// be queried with [`MutationSet::root()`]. Once a mutation set is returned,
    /// [`SparseMerkleTree::apply_mutations()`] can be called in order to commit these changes to
    /// the Merkle tree, or [`drop()`] to discard them.
    fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (Self::Key, Self::Value)>,
    ) -> MutationSet<DEPTH, Self::Key, Self::Value> {
        use NodeMutation::*;

        let mut new_root = self.root();
        let mut new_pairs: UnorderedMap<Self::Key, Self::Value> = Default::default();
        let mut node_mutations: NodeMutations = Default::default();

        for (key, value) in kv_pairs {
            // If the old value and the new value are the same, there is nothing to update.
            // For the unusual case that kv_pairs has multiple values at the same key, we'll have
            // to check the key-value pairs we've already seen to get the "effective" old value.
            let old_value = new_pairs.get(&key).cloned().unwrap_or_else(|| self.get_value(&key));
            if value == old_value {
                continue;
            }

            let leaf_index = Self::key_to_leaf_index(&key);
            let mut node_index = NodeIndex::from(leaf_index);

            // We need the current leaf's hash to calculate the new leaf, but in the rare case that
            // `kv_pairs` has multiple pairs that go into the same leaf, then those pairs are also
            // part of the "current leaf".
            let old_leaf = {
                let pairs_at_index = new_pairs
                    .iter()
                    .filter(|&(new_key, _)| Self::key_to_leaf_index(new_key) == leaf_index);

                pairs_at_index.fold(self.get_leaf(&key), |acc, (k, v)| {
                    // Most of the time `pairs_at_index` should only contain a single entry (or
                    // none at all), as multi-leaves should be really rare.
                    let existing_leaf = acc.clone();
                    self.construct_prospective_leaf(existing_leaf, k, v)
                })
            };

            let new_leaf = self.construct_prospective_leaf(old_leaf, &key, &value);

            let mut new_child_hash = Self::hash_leaf(&new_leaf);

            for node_depth in (0..node_index.depth()).rev() {
                // Whether the node we're replacing is the right child or the left child.
                let is_right = node_index.is_value_odd();
                node_index.move_up();

                let old_node = node_mutations
                    .get(&node_index)
                    .map(|mutation| match mutation {
                        Addition(node) => node.clone(),
                        Removal => EmptySubtreeRoots::get_inner_node(DEPTH, node_depth),
                    })
                    .unwrap_or_else(|| self.get_inner_node(node_index));

                let new_node = if is_right {
                    InnerNode {
                        left: old_node.left,
                        right: new_child_hash,
                    }
                } else {
                    InnerNode {
                        left: new_child_hash,
                        right: old_node.right,
                    }
                };

                // The next iteration will operate on this new node's hash.
                new_child_hash = new_node.hash();

                let &equivalent_empty_hash = EmptySubtreeRoots::entry(DEPTH, node_depth);
                let is_removal = new_child_hash == equivalent_empty_hash;
                let new_entry = if is_removal { Removal } else { Addition(new_node) };
                node_mutations.insert(node_index, new_entry);
            }

            // Once we're at depth 0, the last node we made is the new root.
            new_root = new_child_hash;
            // And then we're done with this pair; on to the next one.
            new_pairs.insert(key, value);
        }

        MutationSet {
            old_root: self.root(),
            new_root,
            node_mutations,
            new_pairs,
        }
    }

    /// Applies the prospective mutations computed with [`SparseMerkleTree::compute_mutations()`] to
    /// this tree.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    fn apply_mutations(
        &mut self,
        mutations: MutationSet<DEPTH, Self::Key, Self::Value>,
    ) -> Result<(), MerkleError>
    where
        Self: Sized,
    {
        use NodeMutation::*;
        let MutationSet {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        } = mutations;

        // Guard against accidentally trying to apply mutations that were computed against a
        // different tree, including a stale version of this tree.
        if old_root != self.root() {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: old_root,
            });
        }

        for (index, mutation) in node_mutations {
            match mutation {
                Removal => {
                    self.remove_inner_node(index);
                },
                Addition(node) => {
                    self.insert_inner_node(index, node);
                },
            }
        }

        for (key, value) in new_pairs {
            self.insert_value(key, value);
        }

        self.set_root(new_root);

        Ok(())
    }

    /// Applies the prospective mutations computed with [`SparseMerkleTree::compute_mutations()`] to
    /// this tree and returns the reverse mutation set. Applying the reverse mutation sets to the
    /// updated tree will revert the changes.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    fn apply_mutations_with_reversion(
        &mut self,
        mutations: MutationSet<DEPTH, Self::Key, Self::Value>,
    ) -> Result<MutationSet<DEPTH, Self::Key, Self::Value>, MerkleError>
    where
        Self: Sized,
    {
        use NodeMutation::*;
        let MutationSet {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        } = mutations;

        // Guard against accidentally trying to apply mutations that were computed against a
        // different tree, including a stale version of this tree.
        if old_root != self.root() {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: old_root,
            });
        }

        let mut reverse_mutations = NodeMutations::new();
        for (index, mutation) in node_mutations {
            match mutation {
                Removal => {
                    if let Some(node) = self.remove_inner_node(index) {
                        reverse_mutations.insert(index, Addition(node));
                    }
                },
                Addition(node) => {
                    if let Some(old_node) = self.insert_inner_node(index, node) {
                        reverse_mutations.insert(index, Addition(old_node));
                    } else {
                        reverse_mutations.insert(index, Removal);
                    }
                },
            }
        }

        let mut reverse_pairs = UnorderedMap::new();
        for (key, value) in new_pairs {
            if let Some(old_value) = self.insert_value(key.clone(), value) {
                reverse_pairs.insert(key, old_value);
            } else {
                reverse_pairs.insert(key, Self::EMPTY_VALUE);
            }
        }

        self.set_root(new_root);

        Ok(MutationSet {
            old_root: new_root,
            node_mutations: reverse_mutations,
            new_pairs: reverse_pairs,
            new_root: old_root,
        })
    }

    // REQUIRED METHODS
    // ---------------------------------------------------------------------------------------------

    /// Construct this type from already computed leaves and nodes. The caller ensures passed
    /// arguments are correct and consistent with each other.
    fn from_raw_parts(
        inner_nodes: InnerNodes,
        leaves: Leaves<Self::Leaf>,
        root: RpoDigest,
    ) -> Result<Self, MerkleError>
    where
        Self: Sized;

    /// The root of the tree
    fn root(&self) -> RpoDigest;

    /// Sets the root of the tree
    fn set_root(&mut self, root: RpoDigest);

    /// Retrieves an inner node at the given index
    fn get_inner_node(&self, index: NodeIndex) -> InnerNode;

    /// Inserts an inner node at the given index
    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode>;

    /// Removes an inner node at the given index
    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode>;

    /// Inserts a leaf node, and returns the value at the key if already exists
    fn insert_value(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value>;

    /// Returns the value at the specified key. Recall that by definition, any key that hasn't been
    /// updated is associated with [`Self::EMPTY_VALUE`].
    fn get_value(&self, key: &Self::Key) -> Self::Value;

    /// Returns the leaf at the specified index.
    fn get_leaf(&self, key: &Self::Key) -> Self::Leaf;

    /// Returns the hash of a leaf
    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest;

    /// Returns what a leaf would look like if a key-value pair were inserted into the tree, without
    /// mutating the tree itself. The existing leaf can be empty.
    ///
    /// To get a prospective leaf based on the current state of the tree, use `self.get_leaf(key)`
    /// as the argument for `existing_leaf`. The return value from this function can be chained back
    /// into this function as the first argument to continue making prospective changes.
    ///
    /// # Invariants
    /// Because this method is for a prospective key-value insertion into a specific leaf,
    /// `existing_leaf` must have the same leaf index as `key` (as determined by
    /// [`SparseMerkleTree::key_to_leaf_index()`]), or the result will be meaningless.
    fn construct_prospective_leaf(
        &self,
        existing_leaf: Self::Leaf,
        key: &Self::Key,
        value: &Self::Value,
    ) -> Self::Leaf;

    /// Maps a key to a leaf index
    fn key_to_leaf_index(key: &Self::Key) -> LeafIndex<DEPTH>;

    /// Constructs a single leaf from an arbitrary amount of key-value pairs.
    /// Those pairs must all have the same leaf index.
    fn pairs_to_leaf(pairs: Vec<(Self::Key, Self::Value)>) -> Self::Leaf;

    /// Maps a (MerklePath, Self::Leaf) to an opening.
    ///
    /// The length `path` is guaranteed to be equal to `DEPTH`
    fn path_and_leaf_to_opening(path: MerklePath, leaf: Self::Leaf) -> Self::Opening;

    /// Performs the initial transforms for constructing a [`SparseMerkleTree`] by composing
    /// subtrees. In other words, this function takes the key-value inputs to the tree, and produces
    /// the inputs to feed into [`build_subtree()`].
    ///
    /// `pairs` *must* already be sorted **by leaf index column**, not simply sorted by key. If
    /// `pairs` is not correctly sorted, the returned computations will be incorrect.
    ///
    /// # Panics
    /// With debug assertions on, this function panics if it detects that `pairs` is not correctly
    /// sorted. Without debug assertions, the returned computations will be incorrect.
    fn sorted_pairs_to_leaves(
        pairs: Vec<(Self::Key, Self::Value)>,
    ) -> PairComputations<u64, Self::Leaf> {
        debug_assert!(pairs.is_sorted_by_key(|(key, _)| Self::key_to_leaf_index(key).value()));

        let mut accumulator: PairComputations<u64, Self::Leaf> = Default::default();
        let mut accumulated_leaves: Vec<SubtreeLeaf> = Vec::with_capacity(pairs.len() / 2);

        // As we iterate, we'll keep track of the kv-pairs we've seen so far that correspond to a
        // single leaf. When we see a pair that's in a different leaf, we'll swap these pairs
        // out and store them in our accumulated leaves.
        let mut current_leaf_buffer: Vec<(Self::Key, Self::Value)> = Default::default();

        let mut iter = pairs.into_iter().peekable();
        while let Some((key, value)) = iter.next() {
            let col = Self::key_to_leaf_index(&key).index.value();
            let peeked_col = iter.peek().map(|(key, _v)| {
                let index = Self::key_to_leaf_index(key);
                let next_col = index.index.value();
                // We panic if `pairs` is not sorted by column.
                debug_assert!(next_col >= col);
                next_col
            });
            current_leaf_buffer.push((key, value));

            // If the next pair is the same column as this one, then we're done after adding this
            // pair to the buffer.
            if peeked_col == Some(col) {
                continue;
            }

            // Otherwise, the next pair is a different column, or there is no next pair. Either way
            // it's time to swap out our buffer.
            let leaf_pairs = mem::take(&mut current_leaf_buffer);
            let leaf = Self::pairs_to_leaf(leaf_pairs);
            let hash = Self::hash_leaf(&leaf);

            accumulator.nodes.insert(col, leaf);
            accumulated_leaves.push(SubtreeLeaf { col, hash });

            debug_assert!(current_leaf_buffer.is_empty());
        }

        // TODO: determine is there is any notable performance difference between computing
        // subtree boundaries after the fact as an iterator adapter (like this), versus computing
        // subtree boundaries as we go. Either way this function is only used at the beginning of a
        // parallel construction, so it should not be a critical path.
        accumulator.leaves = SubtreeLeavesIter::from_leaves(&mut accumulated_leaves).collect();
        accumulator
    }

    /// Computes the raw parts for a new sparse Merkle tree from a set of key-value pairs.
    ///
    /// `entries` need not be sorted. This function will sort them.
    #[cfg(feature = "concurrent")]
    fn build_subtrees(
        mut entries: Vec<(Self::Key, Self::Value)>,
    ) -> (InnerNodes, Leaves<Self::Leaf>) {
        entries.sort_by_key(|item| {
            let index = Self::key_to_leaf_index(&item.0);
            index.value()
        });
        Self::build_subtrees_from_sorted_entries(entries)
    }

    /// Computes the raw parts for a new sparse Merkle tree from a set of key-value pairs.
    ///
    /// This function is mostly an implementation detail of
    /// [`SparseMerkleTree::with_entries_par()`].
    #[cfg(feature = "concurrent")]
    fn build_subtrees_from_sorted_entries(
        entries: Vec<(Self::Key, Self::Value)>,
    ) -> (InnerNodes, Leaves<Self::Leaf>) {
        use rayon::prelude::*;

        let mut accumulated_nodes: InnerNodes = Default::default();

        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: initial_leaves,
        } = Self::sorted_pairs_to_leaves(entries);

        for current_depth in (SUBTREE_DEPTH..=DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
            let (nodes, mut subtree_roots): (Vec<BTreeMap<_, _>>, Vec<SubtreeLeaf>) = leaf_subtrees
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted());
                    debug_assert!(!subtree.is_empty());

                    let (nodes, subtree_root) = build_subtree(subtree, DEPTH, current_depth);
                    (nodes, subtree_root)
                })
                .unzip();

            leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            accumulated_nodes.extend(nodes.into_iter().flatten());

            debug_assert!(!leaf_subtrees.is_empty());
        }
        (accumulated_nodes, initial_leaves)
    }
}

// INNER NODE
// ================================================================================================

/// This struct is public so functions returning it can be used in `benches/`, but is otherwise not
/// part of the public API.
#[doc(hidden)]
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
    pub const fn new_max_depth(value: u64) -> Self {
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
            return Err(MerkleError::InvalidNodeIndexDepth {
                expected: DEPTH,
                provided: node_index.depth(),
            });
        }

        Self::new(node_index.value())
    }
}

// MUTATIONS
// ================================================================================================

/// A change to an inner node of a [`SparseMerkleTree`] that hasn't yet been applied.
/// [`MutationSet`] stores this type in relation to a [`NodeIndex`] to keep track of what changes
/// need to occur at which node indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeMutation {
    /// Corresponds to [`SparseMerkleTree::remove_inner_node()`].
    Removal,
    /// Corresponds to [`SparseMerkleTree::insert_inner_node()`].
    Addition(InnerNode),
}

/// Represents a group of prospective mutations to a `SparseMerkleTree`, created by
/// `SparseMerkleTree::compute_mutations()`, and that can be applied with
/// `SparseMerkleTree::apply_mutations()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MutationSet<const DEPTH: u8, K: Eq + Hash, V> {
    /// The root of the Merkle tree this MutationSet is for, recorded at the time
    /// [`SparseMerkleTree::compute_mutations()`] was called. Exists to guard against applying
    /// mutations to the wrong tree or applying stale mutations to a tree that has since changed.
    old_root: RpoDigest,
    /// The set of nodes that need to be removed or added. The "effective" node at an index is the
    /// Merkle tree's existing node at that index, with the [`NodeMutation`] in this map at that
    /// index overlayed, if any. Each [`NodeMutation::Addition`] corresponds to a
    /// [`SparseMerkleTree::insert_inner_node()`] call, and each [`NodeMutation::Removal`]
    /// corresponds to a [`SparseMerkleTree::remove_inner_node()`] call.
    node_mutations: NodeMutations,
    /// The set of top-level key-value pairs we're prospectively adding to the tree, including
    /// adding empty values. The "effective" value for a key is the value in this BTreeMap, falling
    /// back to the existing value in the Merkle tree. Each entry corresponds to a
    /// [`SparseMerkleTree::insert_value()`] call.
    new_pairs: UnorderedMap<K, V>,
    /// The calculated root for the Merkle tree, given these mutations. Publicly retrievable with
    /// [`MutationSet::root()`]. Corresponds to a [`SparseMerkleTree::set_root()`]. call.
    new_root: RpoDigest,
}

impl<const DEPTH: u8, K: Eq + Hash, V> MutationSet<DEPTH, K, V> {
    /// Returns the SMT root that was calculated during `SparseMerkleTree::compute_mutations()`. See
    /// that method for more information.
    pub fn root(&self) -> RpoDigest {
        self.new_root
    }

    /// Returns the SMT root before the mutations were applied.
    pub fn old_root(&self) -> RpoDigest {
        self.old_root
    }

    /// Returns the set of inner nodes that need to be removed or added.
    pub fn node_mutations(&self) -> &NodeMutations {
        &self.node_mutations
    }

    /// Returns the set of top-level key-value pairs that need to be added, updated or deleted
    /// (i.e. set to `EMPTY_WORD`).
    pub fn new_pairs(&self) -> &UnorderedMap<K, V> {
        &self.new_pairs
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for InnerNode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.left);
        target.write(self.right);
    }
}

impl Deserializable for InnerNode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let left = source.read()?;
        let right = source.read()?;

        Ok(Self { left, right })
    }
}

impl Serializable for NodeMutation {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            NodeMutation::Removal => target.write_bool(false),
            NodeMutation::Addition(inner_node) => {
                target.write_bool(true);
                inner_node.write_into(target);
            },
        }
    }
}

impl Deserializable for NodeMutation {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        if source.read_bool()? {
            let inner_node = source.read()?;
            return Ok(NodeMutation::Addition(inner_node));
        }

        Ok(NodeMutation::Removal)
    }
}

impl<const DEPTH: u8, K: Serializable + Eq + Hash, V: Serializable> Serializable
    for MutationSet<DEPTH, K, V>
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.old_root);
        target.write(self.new_root);

        let inner_removals: Vec<_> = self
            .node_mutations
            .iter()
            .filter(|(_, value)| matches!(value, NodeMutation::Removal))
            .map(|(key, _)| key)
            .collect();
        let inner_additions: Vec<_> = self
            .node_mutations
            .iter()
            .filter_map(|(key, value)| match value {
                NodeMutation::Addition(node) => Some((key, node)),
                _ => None,
            })
            .collect();

        target.write_usize(inner_removals.len());
        target.write_many(inner_removals);

        target.write_usize(inner_additions.len());
        target.write_many(inner_additions);

        target.write_usize(self.new_pairs.len());
        target.write_many(&self.new_pairs);
    }
}

impl<const DEPTH: u8, K: Deserializable + Ord + Eq + Hash, V: Deserializable> Deserializable
    for MutationSet<DEPTH, K, V>
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let old_root = source.read()?;
        let new_root = source.read()?;

        let num_removals = source.read_usize()?;
        let inner_removals: Vec<NodeIndex> = source.read_many(num_removals)?;

        let num_additions = source.read_usize()?;
        let inner_additions: Vec<(NodeIndex, InnerNode)> = source.read_many(num_additions)?;

        let node_mutations = NodeMutations::from_iter(
            inner_removals.into_iter().map(|index| (index, NodeMutation::Removal)).chain(
                inner_additions
                    .into_iter()
                    .map(|(index, node)| (index, NodeMutation::Addition(node))),
            ),
        );

        let num_new_pairs = source.read_usize()?;
        let new_pairs = source.read_many(num_new_pairs)?;
        let new_pairs = UnorderedMap::from_iter(new_pairs);

        Ok(Self {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        })
    }
}

// SUBTREES
// ================================================================================================

/// A subtree is of depth 8.
const SUBTREE_DEPTH: u8 = 8;

/// A depth-8 subtree contains 256 "columns" that can possibly be occupied.
const COLS_PER_SUBTREE: u64 = u64::pow(2, SUBTREE_DEPTH as u32);

/// Helper struct for organizing the data we care about when computing Merkle subtrees.
///
/// Note that these represet "conceptual" leaves of some subtree, not necessarily
/// the leaf type for the sparse Merkle tree.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SubtreeLeaf {
    /// The 'value' field of [`NodeIndex`]. When computing a subtree, the depth is already known.
    pub col: u64,
    /// The hash of the node this `SubtreeLeaf` represents.
    pub hash: RpoDigest,
}

/// Helper struct to organize the return value of [`SparseMerkleTree::sorted_pairs_to_leaves()`].
#[derive(Debug, Clone)]
pub(crate) struct PairComputations<K, L> {
    /// Literal leaves to be added to the sparse Merkle tree's internal mapping.
    pub nodes: UnorderedMap<K, L>,
    /// "Conceptual" leaves that will be used for computations.
    pub leaves: Vec<Vec<SubtreeLeaf>>,
}

// Derive requires `L` to impl Default, even though we don't actually need that.
impl<K, L> Default for PairComputations<K, L> {
    fn default() -> Self {
        Self {
            nodes: Default::default(),
            leaves: Default::default(),
        }
    }
}

#[derive(Debug)]
struct SubtreeLeavesIter<'s> {
    leaves: core::iter::Peekable<alloc::vec::Drain<'s, SubtreeLeaf>>,
}
impl<'s> SubtreeLeavesIter<'s> {
    fn from_leaves(leaves: &'s mut Vec<SubtreeLeaf>) -> Self {
        // TODO: determine if there is any notable performance difference between taking a Vec,
        // which many need flattening first, vs storing a `Box<dyn Iterator<Item = SubtreeLeaf>>`.
        // The latter may have self-referential properties that are impossible to express in purely
        // safe Rust Rust.
        Self { leaves: leaves.drain(..).peekable() }
    }
}
impl Iterator for SubtreeLeavesIter<'_> {
    type Item = Vec<SubtreeLeaf>;

    /// Each `next()` collects an entire subtree.
    fn next(&mut self) -> Option<Vec<SubtreeLeaf>> {
        let mut subtree: Vec<SubtreeLeaf> = Default::default();

        let mut last_subtree_col = 0;

        while let Some(leaf) = self.leaves.peek() {
            last_subtree_col = u64::max(1, last_subtree_col);
            let is_exact_multiple = Integer::is_multiple_of(&last_subtree_col, &COLS_PER_SUBTREE);
            let next_subtree_col = if is_exact_multiple {
                u64::next_multiple_of(last_subtree_col + 1, COLS_PER_SUBTREE)
            } else {
                last_subtree_col.next_multiple_of(COLS_PER_SUBTREE)
            };

            last_subtree_col = leaf.col;
            if leaf.col < next_subtree_col {
                subtree.push(self.leaves.next().unwrap());
            } else if subtree.is_empty() {
                continue;
            } else {
                break;
            }
        }

        if subtree.is_empty() {
            debug_assert!(self.leaves.peek().is_none());
            return None;
        }

        Some(subtree)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds Merkle nodes from a bottom layer of "leaves" -- represented by a horizontal index and
/// the hash of the leaf at that index. `leaves` *must* be sorted by horizontal index, and
/// `leaves` must not contain more than one depth-8 subtree's worth of leaves.
///
/// This function will then calculate the inner nodes above each leaf for 8 layers, as well as
/// the "leaves" for the next 8-deep subtree, so this function can effectively be chained into
/// itself.
///
/// # Panics
/// With debug assertions on, this function panics under invalid inputs: if `leaves` contains
/// more entries than can fit in a depth-8 subtree, if `leaves` contains leaves belonging to
/// different depth-8 subtrees, if `bottom_depth` is lower in the tree than the specified
/// maximum depth (`DEPTH`), or if `leaves` is not sorted.
fn build_subtree(
    mut leaves: Vec<SubtreeLeaf>,
    tree_depth: u8,
    bottom_depth: u8,
) -> (BTreeMap<NodeIndex, InnerNode>, SubtreeLeaf) {
    debug_assert!(bottom_depth <= tree_depth);
    debug_assert!(Integer::is_multiple_of(&bottom_depth, &SUBTREE_DEPTH));
    debug_assert!(leaves.len() <= usize::pow(2, SUBTREE_DEPTH as u32));
    let subtree_root = bottom_depth - SUBTREE_DEPTH;
    let mut inner_nodes: BTreeMap<NodeIndex, InnerNode> = Default::default();
    let mut next_leaves: Vec<SubtreeLeaf> = Vec::with_capacity(leaves.len() / 2);
    for next_depth in (subtree_root..bottom_depth).rev() {
        debug_assert!(next_depth <= bottom_depth);
        // `next_depth` is the stuff we're making.
        // `current_depth` is the stuff we have.
        let current_depth = next_depth + 1;
        let mut iter = leaves.drain(..).peekable();
        while let Some(first) = iter.next() {
            // On non-continuous iterations, including the first iteration, `first_column` may
            // be a left or right node. On subsequent continuous iterations, we will always call
            // `iter.next()` twice.
            // On non-continuous iterations (including the very first iteration), this column
            // could be either on the left or the right. If the next iteration is not
            // discontinuous with our right node, then the next iteration's
            let is_right = first.col.is_odd();
            let (left, right) = if is_right {
                // Discontinuous iteration: we have no left node, so it must be empty.
                let left = SubtreeLeaf {
                    col: first.col - 1,
                    hash: *EmptySubtreeRoots::entry(tree_depth, current_depth),
                };
                let right = first;
                (left, right)
            } else {
                let left = first;
                let right_col = first.col + 1;
                let right = match iter.peek().copied() {
                    Some(SubtreeLeaf { col, .. }) if col == right_col => {
                        // Our inputs must be sorted.
                        debug_assert!(left.col <= col);
                        // The next leaf in the iterator is our sibling. Use it and consume it!
                        iter.next().unwrap()
                    },
                    // Otherwise, the leaves don't contain our sibling, so our sibling must be
                    // empty.
                    _ => SubtreeLeaf {
                        col: right_col,
                        hash: *EmptySubtreeRoots::entry(tree_depth, current_depth),
                    },
                };
                (left, right)
            };
            let index = NodeIndex::new_unchecked(current_depth, left.col).parent();
            let node = InnerNode { left: left.hash, right: right.hash };
            let hash = node.hash();
            let &equivalent_empty_hash = EmptySubtreeRoots::entry(tree_depth, next_depth);
            // If this hash is empty, then it doesn't become a new inner node, nor does it count
            // as a leaf for the next depth.
            if hash != equivalent_empty_hash {
                inner_nodes.insert(index, node);
                next_leaves.push(SubtreeLeaf { col: index.value(), hash });
            }
        }
        // Stop borrowing `leaves`, so we can swap it.
        // The iterator is empty at this point anyway.
        drop(iter);
        // After each depth, consider the stuff we just made the new "leaves", and empty the
        // other collection.
        mem::swap(&mut leaves, &mut next_leaves);
    }
    debug_assert_eq!(leaves.len(), 1);
    let root = leaves.pop().unwrap();
    (inner_nodes, root)
}

#[cfg(feature = "internal")]
pub fn build_subtree_for_bench(
    leaves: Vec<SubtreeLeaf>,
    tree_depth: u8,
    bottom_depth: u8,
) -> (BTreeMap<NodeIndex, InnerNode>, SubtreeLeaf) {
    build_subtree(leaves, tree_depth, bottom_depth)
}

// TESTS
// ================================================================================================
#[cfg(test)]
mod tests;
