use alloc::vec::Vec;
use std::{fs, path::Path};

use heed::{Database, EnvFlags, EnvOpenOptions, byteorder::BigEndian, types::*};
use rayon::prelude::*;

use super::{
    EMPTY_WORD, EmptySubtreeRoots, InnerNode, InnerNodeInfo, InnerNodes, LeafIndex, Leaves,
    MerkleError, MerklePath, MutationSet, NodeIndex, RpoDigest, SMT_DEPTH, Smt, SmtLeaf, SmtProof,
    SparseMerkleTree, Word,
    concurrent::{PairComputations, SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter, build_subtree},
};
use crate::merkle::smt::UnorderedMap;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const IN_MEMORY_DEPTH: u8 = 24;

// TYPES
// ================================================================================================

type NodeIndexKey = (u8, u64);

// LargeSmt
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
#[derive(Debug, Clone)]
pub struct LargeSmt {
    root: RpoDigest,

    env: heed::Env,

    db_inner: Database<SerdeBincode<NodeIndexKey>, SerdeBincode<InnerNode>>,
    db_leaves: Database<U64<BigEndian>, SerdeBincode<SmtLeaf>>,
    in_memory_nodes: Vec<Option<InnerNode>>,
    in_memory_count: usize,
}

impl LargeSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// The default value used to compute the hash of empty leaves
    pub const EMPTY_VALUE: Word = <Self as SparseMerkleTree<SMT_DEPTH>>::EMPTY_VALUE;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [Smt].
    ///
    /// All leaves in the returned tree are set to [Self::EMPTY_VALUE].
    pub fn new(path: &Path) -> Self {
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(1_099_511_627_776) // 1 TB in bytes
                .flags(EnvFlags::NO_SYNC) // Disable sync to disk
                .max_dbs(2)
                .open(std::path::Path::new(path))
                .expect("Failed to open env")
        };

        let mut wtxn = env.write_txn().unwrap();

        let db_inner = env
            .create_database::<SerdeBincode<NodeIndexKey>, SerdeBincode<InnerNode>>(
                &mut wtxn,
                Some("inner_nodes"),
            )
            .unwrap();

        let db_leaves = env
            .create_database::<U64<BigEndian>, SerdeBincode<SmtLeaf>>(&mut wtxn, Some("leaves"))
            .unwrap();

        wtxn.commit().unwrap();

        let num_nodes = (1 << (IN_MEMORY_DEPTH + 1)) - 1;
        let in_memory_nodes = vec![None; num_nodes];

        Self {
            root: *EmptySubtreeRoots::entry(SMT_DEPTH, 0),
            env,
            db_inner,
            db_leaves,
            in_memory_nodes,
            in_memory_count: 0,
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
        path: &Path, entries: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> Result<Self, MerkleError> {
        let entries: Vec<(RpoDigest, Word)> = entries.into_iter().collect();

        if entries.is_empty() {
            return Ok(Self::default());
        }

        let mut tree = LargeSmt::new(path);
        tree.build_subtrees(entries)?;
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
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        let txn = self.env.read_txn().unwrap();
        self.db_leaves.len(&txn).unwrap_or(0) as usize
    }

    /// Returns the number of key-value pairs with non-default values in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    ///
    /// Also note that this is currently an expensive operation is counting the number of entries
    /// requires iterating over all leaves of the tree.
    pub fn num_entries(&self) -> usize {
        //self.entries().count()
        // TODO: implement, currently counts all leaves
        self.num_leaves()
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
        debug_assert_eq!(self.num_leaves() == 0, self.root == Self::EMPTY_ROOT);
        self.root == Self::EMPTY_ROOT
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [Smt].
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        /*self.leaves
        .iter()
        .map(|(leaf_index, leaf)| (LeafIndex::new_max_depth(*leaf_index), leaf))*/
        // TODO: implement
        vec![].into_iter()
    }

    /// Returns an iterator over the key-value pairs of this [Smt].
    pub fn entries(&self) -> impl Iterator<Item = &(RpoDigest, Word)> {
        //self.leaves().flat_map(|(_, leaf)| leaf.entries())
        // TODO: implement
        vec![].into_iter()
    }

    /// Returns an iterator over the inner nodes of this [Smt].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        //self.inner_nodes.values().map(|e| InnerNodeInfo {
        //    value: e.hash(),
        //    left: e.left,
        //    right: e.right,
        //})
        // TODO: implement
        vec![].into_iter()
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
        _kv_pairs: impl IntoIterator<Item = (RpoDigest, Word)>,
    ) -> MutationSet<SMT_DEPTH, RpoDigest, Word> {
        /*#[cfg(feature = "concurrent")]
        {
            self.compute_mutations_concurrent(kmakev_pairs)
        }
        #[cfg(not(feature = "concurrent"))]
        {
            <Self as SparseMerkleTree<SMT_DEPTH>>::compute_mutations(self, kv_pairs)
        }*/
        // TODO: implement
        MutationSet {
            old_root: self.root(),
            new_root: self.root(),
            node_mutations: Default::default(),
            new_pairs: Default::default(),
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

    fn build_subtrees(&mut self, mut entries: Vec<(RpoDigest, Word)>) -> Result<(), MerkleError> {
        entries.par_sort_unstable_by_key(|item| {
            let index = Self::key_to_leaf_index(&item.0);
            index.value()
        });
        self.build_subtrees_from_sorted_entries(entries)?;
        Ok(())
    }

    fn build_subtrees_from_sorted_entries(
        &mut self,
        entries: Vec<(RpoDigest, Word)>,
    ) -> Result<(), MerkleError> {
        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: initial_leaves,
        } = Smt::sorted_pairs_to_leaves(entries)?;
        // If there are no leaves, we can return early

        // Store the leaves in the database
        self.store_leaves_to_db_batch(&initial_leaves);

        if initial_leaves.is_empty() {
            return Ok(());
        }
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
            debug_assert!(!leaf_subtrees.is_empty());

            // Insert the inner nodes into the tree
            self.insert_inner_nodes_batch(nodes.into_iter().flatten());
        }
        self.root = self.get_inner_node(NodeIndex::root()).hash();
        Ok(())
    }

    /// Inserts `value` at leaf index pointed to by `key`. `value` is guaranteed to not be the empty
    /// value, such that this is indeed an insertion.
    fn perform_insert(&mut self, key: RpoDigest, value: Word) -> Option<Word> {
        debug_assert_ne!(value, Self::EMPTY_VALUE);

        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        match self.get_leaf_from_db(&leaf_index) {
            Some(mut leaf) => {
                leaf.insert(key, value);
                self.store_leaf_to_db(leaf_index, &leaf);
                Some(value)
            },
            None => {
                self.store_leaf_to_db(leaf_index, &SmtLeaf::Single((key, value)));
                None
            },
        }
    }

    /// Removes key-value pair at leaf index pointed to by `key` if it exists.
    fn perform_remove(&mut self, key: RpoDigest) -> Option<Word> {
        let leaf_index: LeafIndex<SMT_DEPTH> = Self::key_to_leaf_index(&key);

        if let Some(mut leaf) = self.get_leaf_from_db(&leaf_index) {
            let (old_value, is_empty) = leaf.remove(key);
            if is_empty {
                self.remove_leaf_from_db(leaf_index);
            } else {
                self.store_leaf_to_db(leaf_index, &leaf);
            }
            old_value
        } else {
            // there's nothing stored at the leaf; nothing to update
            None
        }
    }

    fn insert_inner_nodes_batch(
        &mut self,
        nodes: impl IntoIterator<Item = (NodeIndex, InnerNode)>,
    ) {
        let mut txn = self.env.write_txn().unwrap();
        for (index, node) in nodes {
            if index.depth() <= IN_MEMORY_DEPTH {
                let memory_index = to_memory_index(&index);
                self.in_memory_nodes[memory_index] = Some(node);
                self.in_memory_count += 1;
            } else {
                self.db_inner.put(&mut txn, &to_db_key(&index), &node).unwrap();
            }
        }
        txn.commit().unwrap();
    }

    fn get_leaf_from_db(&self, index: &LeafIndex<SMT_DEPTH>) -> Option<SmtLeaf> {
        let txn = self.env.read_txn().unwrap();
        self.db_leaves.get(&txn, &index.value()).ok().flatten()
    }

    fn store_leaf_to_db(&mut self, index: LeafIndex<SMT_DEPTH>, leaf: &SmtLeaf) -> Option<SmtLeaf> {
        let mut txn = self.env.write_txn().unwrap();
        let old = self.db_leaves.get(&txn, &index.value()).unwrap();
        self.db_leaves.put(&mut txn, &index.value(), leaf).unwrap();
        txn.commit().unwrap();
        old
    }

    fn store_leaves_to_db_batch(&mut self, leaves: &Leaves) {
        let mut txn = self.env.write_txn().unwrap();
        for (index, leaf) in leaves {
            self.db_leaves.put(&mut txn, index, leaf).unwrap();
        }
        txn.commit().unwrap();
    }

    fn remove_leaf_from_db(&mut self, index: LeafIndex<SMT_DEPTH>) -> Option<SmtLeaf> {
        let mut txn = self.env.write_txn().unwrap();
        let leaf = self.db_leaves.get(&txn, &index.value()).unwrap();
        self.db_leaves.delete(&mut txn, &index.value()).unwrap();
        txn.commit().unwrap();
        leaf
    }
}

impl SparseMerkleTree<SMT_DEPTH> for LargeSmt {
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
        let path = Path::new("large_smt.db");
        fs::create_dir_all(path).expect("Failed to create database directory");
        let mut smt = Self::new(path);
        smt.insert_inner_nodes_batch(inner_nodes);
        smt.store_leaves_to_db_batch(&leaves);
        smt.set_root(root);

        Ok(smt)
    }

    fn root(&self) -> RpoDigest {
        self.root
    }

    fn set_root(&mut self, root: RpoDigest) {
        self.root = root;
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        if index.depth() <= IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            return self.in_memory_nodes[memory_index]
                .clone()
                .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()));
        }

        let txn = self.env.read_txn().unwrap();
        self.db_inner
            .get(&txn, &to_db_key(&index))
            .ok()
            .flatten()
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        if index.depth() <= IN_MEMORY_DEPTH {
            let i = to_memory_index(&index);
            let old = self.in_memory_nodes[i].replace(inner_node.clone());
            if old.is_none() {
                self.in_memory_count += 1;
            }
            return old;
        }

        let db_key = to_db_key(&index);
        let mut txn = self.env.write_txn().unwrap();
        let old = self.db_inner.get(&txn, &db_key).unwrap();
        self.db_inner.put(&mut txn, &db_key, &inner_node).unwrap();
        txn.commit().unwrap();
        old
    }

    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        if index.depth() <= IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            let old = self.in_memory_nodes.remove(memory_index);
            if old.is_some() {
                self.in_memory_count -= 1;
            }
            return old;
        }

        let db_key = to_db_key(&index);
        let mut txn = self.env.write_txn().unwrap();
        let node = self.db_inner.get(&txn, &db_key).unwrap();
        self.db_inner.delete(&mut txn, &db_key).unwrap();
        txn.commit().unwrap();
        node
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
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key);
        match self.get_leaf_from_db(&leaf_pos) {
            Some(leaf) => leaf.get_value(key).unwrap_or_default(),
            None => EMPTY_WORD,
        }
    }

    fn get_leaf(&self, key: &RpoDigest) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();

        let txn = self.env.read_txn().unwrap();
        let leaf = self.db_leaves.get(&txn, &leaf_pos).ok().flatten();
        match leaf {
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
}

impl PartialEq for LargeSmt {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.num_leaves() == other.num_leaves()
            && self.num_entries() == other.num_entries()
    }
}

impl Eq for LargeSmt {}

impl Default for LargeSmt {
    fn default() -> Self {
        let path = Path::new("large_smt.db");
        fs::create_dir_all(path).expect("Failed to create database directory");
        Self::new(path)
    }
}

fn to_db_key(index: &NodeIndex) -> (u8, u64) {
    (index.depth(), index.value())
}

fn to_memory_index(index: &NodeIndex) -> usize {
    debug_assert!(index.depth() <= IN_MEMORY_DEPTH);
    debug_assert!(index.value() < (1 << index.depth()));
    ((1usize << index.depth()) - 1) + index.value() as usize
}
