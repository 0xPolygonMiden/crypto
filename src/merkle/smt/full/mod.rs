use core::cmp::Ordering;

use winter_math::StarkField;

use crate::hash::rpo::Rpo256;
use crate::merkle::{EmptySubtreeRoots, InnerNodeInfo};
use crate::utils::{
    collections::{BTreeMap, BTreeSet, Vec},
    vec,
};
use crate::{Felt, EMPTY_WORD};

use super::{
    InnerNode, LeafIndex, MerkleError, MerklePath, NodeIndex, RpoDigest, SparseMerkleTree, Word,
};

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
/// All leaves sit at depth 64. A leaf is either empty, or holds one or more key-value pairs. An
/// empty leaf hashes to the empty word. Otherwise, a leaf hashes to the hash of its key-value
/// pairs, ordered by key first, value second.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Smt {
    root: RpoDigest,
    leaves: BTreeMap<u64, SmtLeaf>,
    inner_nodes: BTreeMap<NodeIndex, InnerNode>,
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
            leaves: BTreeMap::new(),
            inner_nodes: BTreeMap::new(),
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

    /// Returns the leaf at the specified index.
    pub fn get_leaf(&self, key: &RpoDigest) -> SmtLeaf {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_leaf(self, key)
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &RpoDigest) -> (MerklePath, SmtLeaf) {
        <Self as SparseMerkleTree<SMT_DEPTH>>::open(self, key)
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

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
            }
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

impl SparseMerkleTree<SMT_DEPTH> for Smt {
    type Key = RpoDigest;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = (MerklePath, SmtLeaf);

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;

    fn root(&self) -> RpoDigest {
        self.root
    }

    fn set_root(&mut self, root: RpoDigest) {
        self.root = root;
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        self.inner_nodes.get(&index).cloned().unwrap_or_else(|| {
            let node = EmptySubtreeRoots::entry(SMT_DEPTH, index.depth() + 1);

            InnerNode { left: *node, right: *node }
        })
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) {
        self.inner_nodes.insert(index, inner_node);
    }

    fn insert_value(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value> {
        // inserting an `EMPTY_VALUE` is equivalent to removing any value associated with `key`
        if value != Self::EMPTY_VALUE {
            self.perform_insert(key, value)
        } else {
            self.perform_remove(key)
        }
    }

    fn get_leaf(&self, key: &RpoDigest) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.clone(),
            None => SmtLeaf::Empty,
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest {
        leaf.hash()
    }

    fn key_to_leaf_index(key: &RpoDigest) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_int())
    }
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

// LEAF
// ================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum SmtLeaf {
    Empty,
    Single((RpoDigest, Word)),
    Multiple(Vec<(RpoDigest, Word)>),
}

impl SmtLeaf {
    /// Converts a leaf to a list of field elements
    pub fn to_elements(&self) -> Vec<Felt> {
        self.clone().into_elements()
    }

    /// Converts a leaf to a list of field elements
    pub fn into_elements(self) -> Vec<Felt> {
        match self {
            SmtLeaf::Empty => Vec::new(),
            SmtLeaf::Single(kv_pair) => kv_to_elements(kv_pair).collect(),
            SmtLeaf::Multiple(kv_pairs) => kv_pairs.into_iter().flat_map(kv_to_elements).collect(),
        }
    }

    /// Computes the hash of the leaf
    pub fn hash(&self) -> RpoDigest {
        match self {
            SmtLeaf::Empty => EMPTY_WORD.into(),
            SmtLeaf::Single((key, value)) => Rpo256::merge(&[*key, value.into()]),
            SmtLeaf::Multiple(kvs) => {
                let elements: Vec<Felt> = kvs.iter().copied().flat_map(kv_to_elements).collect();
                Rpo256::hash_elements(&elements)
            }
        }
    }

    // HELPERS
    // ---------------------------------------------------------------------------------------------

    /// Inserts key-value pair into the leaf; returns the previous value associated with `key`, if
    /// any.
    fn insert(&mut self, key: RpoDigest, value: Word) -> Option<Word> {
        match self {
            SmtLeaf::Empty => {
                *self = SmtLeaf::Single((key, value));
                None
            }
            SmtLeaf::Single(kv_pair) => {
                if kv_pair.0 == key {
                    // the key is already in this leaf. Update the value and return the previous
                    // value
                    let old_value = kv_pair.1;
                    kv_pair.1 = value;
                    Some(old_value)
                } else {
                    // Another entry is present in this leaf. Transform the entry into a list
                    // entry, and make sure the key-value pairs are sorted by key
                    let mut pairs = vec![*kv_pair, (key, value)];
                    pairs.sort_by(|(key_1, _), (key_2, _)| cmp_keys(*key_1, *key_2));

                    *self = SmtLeaf::Multiple(pairs);

                    None
                }
            }
            SmtLeaf::Multiple(kv_pairs) => {
                match kv_pairs.binary_search_by(|kv_pair| cmp_keys(kv_pair.0, key)) {
                    Ok(pos) => {
                        let old_value = kv_pairs[pos].1;
                        kv_pairs[pos].1 = value;

                        Some(old_value)
                    }
                    Err(pos) => {
                        kv_pairs.insert(pos, (key, value));

                        None
                    }
                }
            }
        }
    }

    /// Removes key-value pair from the leaf stored at key; returns the previous value associated
    /// with `key`, if any. Also returns an `is_empty` flag, indicating whether the leaf became
    /// empty, and must be removed from the data structure it is contained in.
    fn remove(&mut self, key: RpoDigest) -> (Option<Word>, bool) {
        match self {
            SmtLeaf::Empty => (None, false),
            SmtLeaf::Single((key_at_leaf, value_at_leaf)) => {
                if *key_at_leaf == key {
                    // our key was indeed stored in the leaf, so we return the value that was stored
                    // in it, and indicate that the leaf should be removed
                    let old_value = *value_at_leaf;

                    // Note: this is not strictly needed, since the caller is expected to drop this
                    // `SmtLeaf` object.
                    *self = SmtLeaf::Empty;

                    (Some(old_value), true)
                } else {
                    // another key is stored at leaf; nothing to update
                    (None, false)
                }
            }
            SmtLeaf::Multiple(kv_pairs) => {
                match kv_pairs.binary_search_by(|kv_pair| cmp_keys(kv_pair.0, key)) {
                    Ok(pos) => {
                        let old_value = kv_pairs[pos].1;

                        kv_pairs.remove(pos);
                        debug_assert!(!kv_pairs.is_empty());

                        if kv_pairs.len() == 1 {
                            // convert the leaf into `Single`
                            *self = SmtLeaf::Single(kv_pairs[0]);
                        }

                        (Some(old_value), false)
                    }
                    Err(_) => {
                        // other keys are stored at leaf; nothing to update
                        (None, false)
                    }
                }
            }
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a key-value tuple to an iterator of `Felt`s
fn kv_to_elements((key, value): (RpoDigest, Word)) -> impl Iterator<Item = Felt> {
    let key_elements = key.into_iter();
    let value_elements = value.into_iter();

    key_elements.chain(value_elements)
}

/// Compares two keys, compared element-by-element using their integer representations starting with
/// the most significant element.
fn cmp_keys(key_1: RpoDigest, key_2: RpoDigest) -> Ordering {
    for (v1, v2) in key_1.iter().zip(key_2.iter()).rev() {
        let v1 = v1.as_int();
        let v2 = v2.as_int();
        if v1 != v2 {
            return v1.cmp(&v2);
        }
    }

    Ordering::Equal
}
