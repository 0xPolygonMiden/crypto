use core::cmp::Ordering;

use winter_math::StarkField;

use crate::hash::rpo::Rpo256;
use crate::utils::collections::Vec;
use crate::Felt;

use super::{
    BTreeMap, EmptySubtreeRoots, InnerNode, LeafIndex, NodeIndex, RpoDigest, SparseMerkleTree, Word,
};

pub const NEW_SMT_DEPTH: u8 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct NewSmt {
    root: RpoDigest,
    leaves: BTreeMap<u64, NewSmtLeaf>,
    inner_nodes: BTreeMap<NodeIndex, InnerNode>,
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

    fn insert_leaf_node(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value> {
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
                    pairs.sort_by(|pair_1, pair_2| cmp_pairs(*pair_1, *pair_2));

                    self.leaves.insert(leaf_index.value(), NewSmtLeaf::Multiple(pairs));

                    None
                }
                NewSmtLeaf::Multiple(_) => todo!(),
            },
            None => {
                self.leaves.insert(leaf_index.value(), NewSmtLeaf::Single((key.clone(), value)));

                Some(Self::Value::default())
            }
        }
    }

    fn get_leaf(&self, key: &Self::Key) -> Self::Leaf {
        let leaf_pos = LeafIndex::<NEW_SMT_DEPTH>::from(*key).value();

        match self.leaves.get(&leaf_pos) {
            Some(leaf) => leaf.clone(),
            None => NewSmtLeaf::Single((
                key.clone(),
                Word::from(*EmptySubtreeRoots::entry(self.depth(), self.depth())),
            )),
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest {
        leaf.hash()
    }
}

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
            NewSmtLeaf::Multiple(kvs) => kvs.into_iter().flat_map(kv_to_elements).collect(),
        };

        Rpo256::hash_elements(&elements)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct NewSmtKey {
    word: Word,
}

impl From<NewSmtKey> for LeafIndex<NEW_SMT_DEPTH> {
    fn from(key: NewSmtKey) -> Self {
        let most_significant_felt = key.word[0];
        Self::new_max_depth(most_significant_felt.inner())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Compares two (key-value) pairs, ordered first by keys, then values.
///
/// Both keys and values are compared element-by-element using their integer representations
/// starting with the most significant element.
fn cmp_pairs((key_1, value_1): (NewSmtKey, Word), (key_2, value_2): (NewSmtKey, Word)) -> Ordering {
    let key_order = cmp_words(key_1.word, key_2.word);

    if key_order != Ordering::Equal {
        key_order
    } else {
        cmp_words(value_1, value_2)
    }
}

fn cmp_words(w1: Word, w2: Word) -> Ordering {
    for (v1, v2) in w1.iter().zip(w2.iter()).rev() {
        let v1 = v1.as_int();
        let v2 = v2.as_int();
        if v1 != v2 {
            return v1.cmp(&v2);
        }
    }

    Ordering::Equal
}
