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
        match self.leaves.get(&leaf_index.value()) {
            Some(leaf) => match leaf {
                NewSmtLeaf::Single(kv_pair) => todo!(),
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
