use crate::hash::rpo::Rpo256;
use crate::Felt;

use super::{
    BTreeMap, EmptySubtreeRoots, InnerNode, LeafIndex, NodeIndex, RpoDigest, SparseMerkleTree, Word,
};

pub const NEW_SMT_DEPTH: u8 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct NewSmt {
    root: RpoDigest,
    leaves: BTreeMap<u64, Word>,
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
        todo!()
    }

    fn get_leaf(&self, key: &Self::Key) -> Self::Leaf {
        todo!()
    }

    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest {
        leaf.hash()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum NewSmtLeaf {
    Single((u64, Word)),
    Multiple(Vec<(u64, Word)>),
}

impl NewSmtLeaf {
    pub fn hash(&self) -> RpoDigest {
        fn tuple_to_elements((key, value): &(u64, Word)) -> impl Iterator<Item = Felt> + '_ {
            let key_ele = Felt::from(*key);
            let value_eles = value.iter().copied();

            std::iter::once(key_ele).chain(value_eles)
        }

        let elements: Vec<Felt> = match self {
            NewSmtLeaf::Single(tuple) => tuple_to_elements(tuple).collect(),
            NewSmtLeaf::Multiple(tuples) => {
                tuples.into_iter().flat_map(tuple_to_elements).collect()
            }
        };

        Rpo256::hash_elements(&elements)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NewSmtKey {
    word: Word,
}

impl From<NewSmtKey> for LeafIndex<NEW_SMT_DEPTH> {
    fn from(key: NewSmtKey) -> Self {
        let most_significant_felt = key.word[0];
        Self::new_max_depth(most_significant_felt.inner())
    }
}
