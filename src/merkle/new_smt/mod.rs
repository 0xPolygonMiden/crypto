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

pub const NEW_SMT_DEPTH: u8 = 64;

// SMT
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct NewSmt {
    root: RpoDigest,
    leaves: BTreeMap<u64, NewSmtLeaf>,
    inner_nodes: BTreeMap<NodeIndex, InnerNode>,
}

impl NewSmt {
    /// Returns a new [NewSmt].
    ///
    /// All leaves in the returned tree are set to [ZERO; 4].
    pub fn new() -> Self {
        let root = *EmptySubtreeRoots::entry(NEW_SMT_DEPTH, 0);

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
        entries: impl IntoIterator<Item = (NewSmtKey, Word)>,
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
                    LeafIndex::<NEW_SMT_DEPTH>::from(key).value(),
                ));
            }

            if value == EMPTY_WORD {
                key_set_to_zero.insert(key);
            };
        }
        Ok(tree)
    }
}

impl SparseMerkleTree<NEW_SMT_DEPTH> for NewSmt {
    type Key = NewSmtKey;

    type Value = Word;

    type Leaf = NewSmtLeaf;

    fn root(&self) -> RpoDigest {
        self.root
    }

    fn set_root(&mut self, root: RpoDigest) {
        self.root = root;
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        self.inner_nodes.get(&index).cloned().unwrap_or_else(|| {
            let node = EmptySubtreeRoots::entry(self.depth(), index.depth() + 1);

            InnerNode { left: *node, right: *node }
        })
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) {
        self.inner_nodes.insert(index, inner_node);
    }

    fn insert_value(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value> {
        let leaf_index: LeafIndex<NEW_SMT_DEPTH> = key.into();
        match self.leaves.get_mut(&leaf_index.value()) {
            Some(leaf) => match leaf {
                NewSmtLeaf::Single(kv_pair) => {
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

                    self.leaves.insert(leaf_index.value(), NewSmtLeaf::Multiple(pairs));

                    None
                }
                NewSmtLeaf::Multiple(kv_pairs) => {
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
                self.leaves.insert(leaf_index.value(), NewSmtLeaf::Single((key, value)));

                Some(Self::Value::default())
            }
        }
    }

    fn get_leaf(&self, key: &Self::Key) -> Self::Leaf {
        let leaf_pos = LeafIndex::<NEW_SMT_DEPTH>::from(*key).value();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.clone(),
            None => NewSmtLeaf::Single((
                *key,
                Word::from(*EmptySubtreeRoots::entry(self.depth(), self.depth())),
            )),
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest {
        leaf.hash()
    }
}

impl Default for NewSmt {
    fn default() -> Self {
        Self::new()
    }
}

// KEY
// ================================================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct NewSmtKey {
    word: Word,
}

impl From<NewSmtKey> for LeafIndex<NEW_SMT_DEPTH> {
    fn from(key: NewSmtKey) -> Self {
        let most_significant_felt = key.word[0];
        Self::new_max_depth(most_significant_felt.as_int())
    }
}

impl Ord for NewSmtKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Note that the indices are reversed. This is because a `Word` is treated as little-endian
        // (i.e. most significant Felt is at index 3). In comparing integer arrays, we want to
        // compare the most significant felts first, and so on until the least signifcant felt.
        let self_word: [u64; 4] = [
            self.word[3].as_int(),
            self.word[2].as_int(),
            self.word[1].as_int(),
            self.word[0].as_int(),
        ];
        let other_word: [u64; 4] = [
            other.word[3].as_int(),
            other.word[2].as_int(),
            other.word[1].as_int(),
            other.word[0].as_int(),
        ];

        self_word.cmp(&other_word)
    }
}

impl PartialOrd for NewSmtKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// LEAF
// ================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum NewSmtLeaf {
    Single((NewSmtKey, Word)),
    Multiple(Vec<(NewSmtKey, Word)>),
}

impl NewSmtLeaf {
    pub fn hash(&self) -> RpoDigest {
        fn kv_to_elements((key, value): &(NewSmtKey, Word)) -> impl Iterator<Item = Felt> + '_ {
            let key_elements = key.word.iter().copied();
            let value_elements = value.iter().copied();

            key_elements.chain(value_elements)
        }

        let elements: Vec<Felt> = match self {
            NewSmtLeaf::Single(kv) => kv_to_elements(kv).collect(),
            NewSmtLeaf::Multiple(kvs) => kvs.iter().flat_map(kv_to_elements).collect(),
        };

        Rpo256::hash_elements(&elements)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Compares two keys, compared element-by-element using their integer representations starting with
/// the most significant element.
fn cmp_keys(key_1: NewSmtKey, key_2: NewSmtKey) -> Ordering {
    for (v1, v2) in key_1.word.iter().zip(key_2.word.iter()).rev() {
        let v1 = v1.as_int();
        let v2 = v2.as_int();
        if v1 != v2 {
            return v1.cmp(&v2);
        }
    }

    Ordering::Equal
}
