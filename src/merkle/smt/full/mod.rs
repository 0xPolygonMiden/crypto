use alloc::{collections::BTreeSet, string::ToString, vec::Vec};
use core::mem;

use num::Integer;

use super::{
    EmptySubtreeRoots, Felt, InnerNode, InnerNodeInfo, InnerNodes, LeafIndex, MerkleError,
    MerklePath, MutationSet, NodeIndex, NodeMutation, NodeMutations, Rpo256, RpoDigest,
    SparseMerkleTree, UnorderedMap, Word, EMPTY_WORD,
};

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

type Leaves = super::Leaves<SmtLeaf>;
type MutatedSubtreeLeaves = Vec<Vec<SubtreeLeaf>>;

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
    inner_nodes: InnerNodes,
    leaves: Leaves,
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
            inner_nodes: Default::default(),
            leaves: Default::default(),
        }
    }

    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// If the `concurrent` feature is enabled, this function uses a parallel implementation to
    /// process the entries efficiently, otherwise it defaults to the sequential implementation.
    ///
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    pub fn with_entries(
        entries: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> Result<Self, MerkleError> {
        #[cfg(feature = "concurrent")]
        {
            Self::with_entries_concurrent(entries)
        }
        #[cfg(not(feature = "concurrent"))]
        {
            Self::with_entries_sequential(entries)
        }
    }

    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// This sequential implementation processes entries one at a time to build the tree.
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    pub fn with_entries_sequential(
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

    /// Returns a new [`Smt`] instantiated from already computed leaves and nodes.
    ///
    /// This function performs minimal consistency checking. It is the caller's responsibility to
    /// ensure the passed arguments are correct and consistent with each other.
    ///
    /// # Panics
    /// With debug assertions on, this function panics if `root` does not match the root node in
    /// `inner_nodes`.
    pub fn from_raw_parts(inner_nodes: InnerNodes, leaves: Leaves, root: RpoDigest) -> Self {
        // Our particular implementation of `from_raw_parts()` never returns `Err`.
        <Self as SparseMerkleTree<SMT_DEPTH>>::from_raw_parts(inner_nodes, leaves, root).unwrap()
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

    /// Returns the number of non-empty leaves in this tree.
    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
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

    /// Returns a boolean value indicating whether the SMT is empty.
    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.leaves.is_empty(), self.root == Self::EMPTY_ROOT);
        self.root == Self::EMPTY_ROOT
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
        #[cfg(feature = "concurrent")]
        {
            self.compute_mutations_concurrent(kv_pairs)
        }
        #[cfg(not(feature = "concurrent"))]
        {
            <Self as SparseMerkleTree<SMT_DEPTH>>::compute_mutations(self, kv_pairs)
        }
    }

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree.
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

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree
    /// and returns the reverse mutation set.
    ///
    /// Applying the reverse mutation sets to the updated tree will revert the changes.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations_with_reversion(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, RpoDigest, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, RpoDigest, Word>, MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::apply_mutations_with_reversion(self, mutations)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Inserts `value` at leaf index pointed to by `key`. `value` is guaranteed to not be the empty
    /// value, such that this is indeed an insertion.
    fn perform_insert(&mut self, key: RpoDigest, value: Word) -> Option<Word> {
        debug_assert_ne!(value, Self::EMPTY_VALUE);

        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        match self.leaves.get_mut(&leaf_index.value()) {
            Some(leaf) => leaf.insert(key, value),
            None => {
                self.leaves.insert(leaf_index.value(), SmtLeaf::Single((key, value)));

                None
            },
        }
    }

    /// Removes key-value pair at leaf index pointed to by `key` if it exists.
    fn perform_remove(&mut self, key: RpoDigest) -> Option<Word> {
        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        if let Some(leaf) = self.leaves.get_mut(&leaf_index.value()) {
            let (old_value, is_empty) = leaf.remove(key);
            if is_empty {
                self.leaves.remove(&leaf_index.value());
            }
            old_value
        } else {
            // there's nothing stored at the leaf; nothing to update
            None
        }
    }
}

// Concurrent implementation
#[cfg(feature = "concurrent")]
impl Smt {
    /// Parallel implementation of [`Smt::with_entries()`].
    ///
    /// This method constructs a new sparse Merkle tree concurrently by processing subtrees in
    /// parallel, working from the bottom up. The process works as follows:
    ///
    /// 1. First, the input key-value pairs are sorted and grouped into subtrees based on their leaf
    ///    indices. Each subtree covers a range of 256 (2^8) possible leaf positions.
    ///
    /// 2. The subtrees are then processed in parallel:
    ///    - For each subtree, compute the inner nodes from depth D down to depth D-8.
    ///    - Each subtree computation yields a new subtree root and its associated inner nodes.
    ///
    /// 3. These subtree roots are recursively merged to become the "leaves" for the next iteration,
    ///    which processes the next 8 levels up. This continues until the final root of the tree is
    ///    computed at depth 0.
    pub fn with_entries_concurrent(
        entries: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> Result<Self, MerkleError> {
        let mut seen_keys = BTreeSet::new();
        let entries: Vec<_> = entries
            .into_iter()
            .map(|(key, value)| {
                if seen_keys.insert(key) {
                    Ok((key, value))
                } else {
                    Err(MerkleError::DuplicateValuesForIndex(
                        LeafIndex::<SMT_DEPTH>::from(key).value(),
                    ))
                }
            })
            .collect::<Result<_, _>>()?;
        if entries.is_empty() {
            return Ok(Self::default());
        }
        let (inner_nodes, leaves) = Self::build_subtrees(entries);
        let root = inner_nodes.get(&NodeIndex::root()).unwrap().hash();
        <Self as SparseMerkleTree<SMT_DEPTH>>::from_raw_parts(inner_nodes, leaves, root)
    }

    /// Parallel implementation of [`Smt::compute_mutations()`].
    ///
    /// This method computes mutations by recursively processing subtrees in parallel, working from
    /// the bottom up. The process works as follows:
    ///
    /// 1. First, the input key-value pairs are sorted and grouped into subtrees based on their leaf
    ///    indices. Each subtree covers a range of 256 (2^8) possible leaf positions.
    ///
    /// 2. The subtrees containing modifications are then processed in parallel:
    ///    - For each modified subtree, compute node mutations from depth D up to depth D-8
    ///    - Each subtree computation yields a new root at depth D-8 and its associated mutations
    ///
    /// 3. These subtree roots become the "leaves" for the next iteration, which processes the next
    ///    8 levels up. This continues until reaching the tree's root at depth 0.
    pub fn compute_mutations_concurrent(
        &self,
        kv_pairs: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> MutationSet<SMT_DEPTH, RpoDigest, Word>
    where
        Self: Sized + Sync,
    {
        use rayon::prelude::*;

        // Collect and sort key-value pairs by their corresponding leaf index
        let mut sorted_kv_pairs: Vec<_> = kv_pairs.into_iter().collect();
        sorted_kv_pairs.par_sort_unstable_by_key(|(key, _)| Self::key_to_leaf_index(key).value());

        // Convert sorted pairs into mutated leaves and capture any new pairs
        let (mut subtree_leaves, new_pairs) =
            self.sorted_pairs_to_mutated_subtree_leaves(sorted_kv_pairs);
        let mut node_mutations = NodeMutations::default();

        // Process each depth level in reverse, stepping by the subtree depth
        for depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
            // Parallel processing of each subtree to generate mutations and roots
            let (mutations_per_subtree, mut subtree_roots): (Vec<_>, Vec<_>) = subtree_leaves
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted() && !subtree.is_empty());
                    self.build_subtree_mutations(subtree, SMT_DEPTH, depth)
                })
                .unzip();

            // Prepare leaves for the next depth level
            subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();

            // Aggregate all node mutations
            node_mutations.extend(mutations_per_subtree.into_iter().flatten());

            debug_assert!(!subtree_leaves.is_empty());
        }

        // Finalize the mutation set with updated roots and mutations
        MutationSet {
            old_root: self.root(),
            new_root: subtree_leaves[0][0].hash,
            node_mutations,
            new_pairs,
        }
    }

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
    fn sorted_pairs_to_leaves(pairs: Vec<(RpoDigest, Word)>) -> PairComputations<u64, SmtLeaf> {
        Self::process_sorted_pairs_to_leaves(pairs, Self::pairs_to_leaf)
    }

    /// Computes leaves from a set of key-value pairs and current leaf values.
    /// Derived from `sorted_pairs_to_leaves`
    fn sorted_pairs_to_mutated_subtree_leaves(
        &self,
        pairs: Vec<(RpoDigest, Word)>,
    ) -> (MutatedSubtreeLeaves, UnorderedMap<RpoDigest, Word>) {
        // Map to track new key-value pairs for mutated leaves
        let mut new_pairs = UnorderedMap::new();

        let accumulator = Self::process_sorted_pairs_to_leaves(pairs, |leaf_pairs| {
            let mut leaf = self.get_leaf(&leaf_pairs[0].0);

            for (key, value) in leaf_pairs {
                // Check if the value has changed
                let old_value =
                    new_pairs.get(&key).cloned().unwrap_or_else(|| self.get_value(&key));

                // Skip if the value hasn't changed
                if value == old_value {
                    continue;
                }

                // Otherwise, update the leaf and track the new key-value pair
                leaf = self.construct_prospective_leaf(leaf, &key, &value);
                new_pairs.insert(key, value);
            }

            leaf
        });
        (accumulator.leaves, new_pairs)
    }

    /// Computes the node mutations and the root of a subtree
    fn build_subtree_mutations(
        &self,
        mut leaves: Vec<SubtreeLeaf>,
        tree_depth: u8,
        bottom_depth: u8,
    ) -> (NodeMutations, SubtreeLeaf)
    where
        Self: Sized,
    {
        debug_assert!(bottom_depth <= tree_depth);
        debug_assert!(Integer::is_multiple_of(&bottom_depth, &SUBTREE_DEPTH));
        debug_assert!(leaves.len() <= usize::pow(2, SUBTREE_DEPTH as u32));

        let subtree_root_depth = bottom_depth - SUBTREE_DEPTH;
        let mut node_mutations: NodeMutations = Default::default();
        let mut next_leaves: Vec<SubtreeLeaf> = Vec::with_capacity(leaves.len() / 2);

        for current_depth in (subtree_root_depth..bottom_depth).rev() {
            debug_assert!(current_depth <= bottom_depth);

            let next_depth = current_depth + 1;
            let mut iter = leaves.drain(..).peekable();

            while let Some(first_leaf) = iter.next() {
                // This constructs a valid index because next_depth will never exceed the depth of
                // the tree.
                let parent_index = NodeIndex::new_unchecked(next_depth, first_leaf.col).parent();
                let parent_node = self.get_inner_node(parent_index);
                let combined_node = Self::fetch_sibling_pair(&mut iter, first_leaf, parent_node);
                let combined_hash = combined_node.hash();

                let &empty_hash = EmptySubtreeRoots::entry(tree_depth, current_depth);

                // Add the parent node even if it is empty for proper upward updates
                next_leaves.push(SubtreeLeaf {
                    col: parent_index.value(),
                    hash: combined_hash,
                });

                node_mutations.insert(
                    parent_index,
                    if combined_hash != empty_hash {
                        NodeMutation::Addition(combined_node)
                    } else {
                        NodeMutation::Removal
                    },
                );
            }
            drop(iter);
            leaves = mem::take(&mut next_leaves);
        }

        debug_assert_eq!(leaves.len(), 1);
        let root_leaf = leaves.pop().unwrap();
        (node_mutations, root_leaf)
    }

    /// Constructs an `InnerNode` representing the sibling pair of which `first_leaf` is a part:
    /// - If `first_leaf` is a right child, the left child is copied from the `parent_node`.
    /// - If `first_leaf` is a left child, the right child is taken from `iter` if it was also
    ///   mutated or copied from the `parent_node`.
    ///
    /// Returns the `InnerNode` containing the hashes of the sibling pair.
    fn fetch_sibling_pair(
        iter: &mut core::iter::Peekable<alloc::vec::Drain<SubtreeLeaf>>,
        first_leaf: SubtreeLeaf,
        parent_node: InnerNode,
    ) -> InnerNode {
        let is_right_node = first_leaf.col.is_odd();

        if is_right_node {
            let left_leaf = SubtreeLeaf {
                col: first_leaf.col - 1,
                hash: parent_node.left,
            };
            InnerNode {
                left: left_leaf.hash,
                right: first_leaf.hash,
            }
        } else {
            let right_col = first_leaf.col + 1;
            let right_leaf = match iter.peek().copied() {
                Some(SubtreeLeaf { col, .. }) if col == right_col => iter.next().unwrap(),
                _ => SubtreeLeaf { col: right_col, hash: parent_node.right },
            };
            InnerNode {
                left: first_leaf.hash,
                right: right_leaf.hash,
            }
        }
    }

    /// Processes sorted key-value pairs to compute leaves for a subtree.
    ///
    /// This function groups key-value pairs by their corresponding column index and processes each
    /// group to construct leaves. The actual construction of the leaf is delegated to the
    /// `process_leaf` callback, allowing flexibility for different use cases (e.g., creating
    /// new leaves or mutating existing ones).
    ///
    /// # Parameters
    /// - `pairs`: A vector of sorted key-value pairs. The pairs *must* be sorted by leaf index
    ///   column (not simply by key). If the input is not sorted correctly, the function will
    ///   produce incorrect results and may panic in debug mode.
    /// - `process_leaf`: A callback function used to process each group of key-value pairs
    ///   corresponding to the same column index. The callback takes a vector of key-value pairs for
    ///   a single column and returns the constructed leaf for that column.
    ///
    /// # Returns
    /// A `PairComputations<u64, Self::Leaf>` containing:
    /// - `nodes`: A mapping of column indices to the constructed leaves.
    /// - `leaves`: A collection of `SubtreeLeaf` structures representing the processed leaves. Each
    ///   `SubtreeLeaf` includes the column index and the hash of the corresponding leaf.
    ///
    /// # Panics
    /// This function will panic in debug mode if the input `pairs` are not sorted by column index.
    fn process_sorted_pairs_to_leaves<F>(
        pairs: Vec<(RpoDigest, Word)>,
        mut process_leaf: F,
    ) -> PairComputations<u64, SmtLeaf>
    where
        F: FnMut(Vec<(RpoDigest, Word)>) -> SmtLeaf,
    {
        use rayon::prelude::*;
        debug_assert!(pairs.is_sorted_by_key(|(key, _)| Self::key_to_leaf_index(key).value()));

        let mut accumulator: PairComputations<u64, SmtLeaf> = Default::default();

        // As we iterate, we'll keep track of the kv-pairs we've seen so far that correspond to a
        // single leaf. When we see a pair that's in a different leaf, we'll swap these pairs
        // out and store them in our accumulated leaves.
        let mut current_leaf_buffer: Vec<(RpoDigest, Word)> = Default::default();

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
            let leaf = process_leaf(leaf_pairs);

            accumulator.nodes.insert(col, leaf);

            debug_assert!(current_leaf_buffer.is_empty());
        }

        // Compute the leaves from the nodes concurrently
        let mut accumulated_leaves: Vec<SubtreeLeaf> = accumulator
            .nodes
            .clone()
            .into_par_iter()
            .map(|(col, leaf)| SubtreeLeaf { col, hash: Self::hash_leaf(&leaf) })
            .collect();

        // Sort the leaves by column
        accumulated_leaves.par_sort_by_key(|leaf| leaf.col);

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
    fn build_subtrees(mut entries: Vec<(RpoDigest, Word)>) -> (InnerNodes, Leaves) {
        entries.sort_by_key(|item| {
            let index = Self::key_to_leaf_index(&item.0);
            index.value()
        });
        Self::build_subtrees_from_sorted_entries(entries)
    }

    /// Computes the raw parts for a new sparse Merkle tree from a set of key-value pairs.
    ///
    /// This function is mostly an implementation detail of
    /// [`Smt::with_entries_concurrent()`].
    fn build_subtrees_from_sorted_entries(entries: Vec<(RpoDigest, Word)>) -> (InnerNodes, Leaves) {
        use rayon::prelude::*;

        let mut accumulated_nodes: InnerNodes = Default::default();

        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: initial_leaves,
        } = Self::sorted_pairs_to_leaves(entries);

        for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
            let (nodes, mut subtree_roots): (Vec<UnorderedMap<_, _>>, Vec<SubtreeLeaf>) =
                leaf_subtrees
                    .into_par_iter()
                    .map(|subtree| {
                        debug_assert!(subtree.is_sorted());
                        debug_assert!(!subtree.is_empty());
                        let (nodes, subtree_root) =
                            build_subtree(subtree, SMT_DEPTH, current_depth);
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

impl SparseMerkleTree<SMT_DEPTH> for Smt {
    type Key = RpoDigest;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = SmtProof;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;
    const EMPTY_ROOT: RpoDigest = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

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
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        self.inner_nodes.insert(index, inner_node)
    }

    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        self.inner_nodes.remove(&index)
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

    fn key_to_leaf_index(key: &RpoDigest) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_int())
    }

    fn path_and_leaf_to_opening(path: MerklePath, leaf: SmtLeaf) -> SmtProof {
        SmtProof::new_unchecked(path, leaf)
    }

    fn pairs_to_leaf(mut pairs: Vec<(RpoDigest, Word)>) -> SmtLeaf {
        assert!(!pairs.is_empty());

        if pairs.len() > 1 {
            SmtLeaf::new_multiple(pairs).unwrap()
        } else {
            let (key, value) = pairs.pop().unwrap();
            // TODO: should we ever be constructing empty leaves from pairs?
            if value == Self::EMPTY_VALUE {
                let index = Self::key_to_leaf_index(&key);
                SmtLeaf::new_empty(index)
            } else {
                SmtLeaf::new_single(key, value)
            }
        }
    }
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
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

    fn get_size_hint(&self) -> usize {
        let entries_count = self.entries().count();

        // Each entry is the size of a digest plus a word.
        entries_count.get_size_hint()
            + entries_count * (RpoDigest::SERIALIZED_SIZE + EMPTY_WORD.get_size_hint())
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
    assert_eq!(bytes.len(), smt_default.get_size_hint());

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
    assert_eq!(bytes.len(), smt.get_size_hint());
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

/// Helper struct to organize the return value of [`Smt::sorted_pairs_to_leaves()`].
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
#[cfg(feature = "concurrent")]
fn build_subtree(
    mut leaves: Vec<SubtreeLeaf>,
    tree_depth: u8,
    bottom_depth: u8,
) -> (UnorderedMap<NodeIndex, InnerNode>, SubtreeLeaf) {
    debug_assert!(bottom_depth <= tree_depth);
    debug_assert!(Integer::is_multiple_of(&bottom_depth, &SUBTREE_DEPTH));
    debug_assert!(leaves.len() <= usize::pow(2, SUBTREE_DEPTH as u32));
    let subtree_root = bottom_depth - SUBTREE_DEPTH;
    let mut inner_nodes: UnorderedMap<NodeIndex, InnerNode> = Default::default();
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
) -> (UnorderedMap<NodeIndex, InnerNode>, SubtreeLeaf) {
    build_subtree(leaves, tree_depth, bottom_depth)
}
