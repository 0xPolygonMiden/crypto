use core::cmp::Ordering;

use winter_math::StarkField;

use crate::hash::rpo::Rpo256;
use crate::utils::{collections::Vec, vec};
use crate::{Felt, EMPTY_WORD};

use super::{
    BTreeMap, BTreeSet, EmptySubtreeRoots, InnerNode, LeafIndex, MerkleError, NodeIndex, RpoDigest,
    SparseMerkleTree, Word,
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

pub const SMT_DEPTH: u8 = 64;

// SMT
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Smt {
    root: RpoDigest,
    leaves: BTreeMap<u64, SmtLeaf>,
    inner_nodes: BTreeMap<NodeIndex, InnerNode>,
}

impl Smt {
    /// Returns a new [NewSmt].
    ///
    /// All leaves in the returned tree are set to [ZERO; 4].
    pub fn new() -> Self {
        let root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

        Self {
            root,
            leaves: BTreeMap::new(),
            inner_nodes: BTreeMap::new(),
        }
    }

    /// Returns a new [SimpleSmt] instantiated with leaves set as specified by the provided entries.
    ///
    /// All leaves omitted from the entries list are set to [ZERO; 4].
    ///
    /// # Errors
    /// Returns an error if:
    /// - The number of entries exceeds 2^63 entries.
    /// - The provided entries contain multiple values for the same key.
    pub fn with_entries(
        entries: impl IntoIterator<Item = (SmtKey, Word)>,
    ) -> Result<Self, MerkleError> {
        // create an empty tree
        let mut tree = Self::new();

        // This being a sparse data structure, the EMPTY_WORD is not assigned to the `BTreeMap`, so
        // entries with the empty value need additional tracking.
        let mut key_set_to_zero = BTreeSet::new();

        for (key, value) in entries {
            let old_value = tree.update_leaf(key, value);

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
}

impl SparseMerkleTree<SMT_DEPTH> for Smt {
    type Key = SmtKey;
    type Value = Word;
    type Leaf = SmtLeaf;

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
        let leaf_index: LeafIndex<SMT_DEPTH> = key.into();
        match self.leaves.get_mut(&leaf_index.value()) {
            Some(leaf) => match leaf {
                SmtLeaf::Single(kv_pair) => {
                    // if the key is already in this entry, update the value and return
                    if kv_pair.0 == key {
                        let old_value = kv_pair.1;
                        kv_pair.1 = value;
                        return Some(old_value);
                    }

                    // transform the entry into a list entry, and make sure the key-value pairs
                    // are sorted by key
                    let mut pairs = vec![*kv_pair, (key, value)];
                    pairs.sort_by(|(key_1, _), (key_2, _)| cmp_keys(*key_1, *key_2));

                    self.leaves.insert(leaf_index.value(), SmtLeaf::Multiple(pairs));

                    None
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
            },
            None => {
                self.leaves.insert(leaf_index.value(), SmtLeaf::Single((key, value)));

                Some(Self::Value::default())
            }
        }
    }

    fn get_leaf(&self, key: &Self::Key) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.clone(),
            None => {
                SmtLeaf::Single((*key, Word::from(*EmptySubtreeRoots::entry(SMT_DEPTH, SMT_DEPTH))))
            }
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest {
        leaf.hash()
    }
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

// SMT KEY
// ================================================================================================

/// Represents a key (256 bits) for the Smt.
///
/// The most significant `u64` determines the corresponding leaf index when inserting values into
/// the Smt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SmtKey {
    word: RpoDigest,
}

impl From<SmtKey> for LeafIndex<SMT_DEPTH> {
    fn from(key: SmtKey) -> Self {
        let most_significant_felt = key.word[0];
        Self::new_max_depth(most_significant_felt.as_int())
    }
}

// LEAF
// ================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum SmtLeaf {
    Single((SmtKey, Word)),
    Multiple(Vec<(SmtKey, Word)>),
}

impl SmtLeaf {
    pub fn hash(&self) -> RpoDigest {
        fn kv_to_elements((key, value): &(SmtKey, Word)) -> impl Iterator<Item = Felt> + '_ {
            let key_elements = key.word.iter().copied();
            let value_elements = value.iter().copied();

            key_elements.chain(value_elements)
        }

        let elements: Vec<Felt> = match self {
            SmtLeaf::Single(kv) => kv_to_elements(kv).collect(),
            SmtLeaf::Multiple(kvs) => kvs.iter().flat_map(kv_to_elements).collect(),
        };

        Rpo256::hash_elements(&elements)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Compares two keys, compared element-by-element using their integer representations starting with
/// the most significant element.
fn cmp_keys(key_1: SmtKey, key_2: SmtKey) -> Ordering {
    for (v1, v2) in key_1.word.iter().zip(key_2.word.iter()).rev() {
        let v1 = v1.as_int();
        let v2 = v2.as_int();
        if v1 != v2 {
            return v1.cmp(&v2);
        }
    }

    Ordering::Equal
}
