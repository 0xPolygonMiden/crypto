use super::{BTreeMap, InnerNode, LeafIndex, NodeIndex, RpoDigest, SparseMerkleTree, Word};

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
        todo!()
    }

    fn set_root(&mut self, root: RpoDigest) {
        todo!()
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        todo!()
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) {
        todo!()
    }

    fn insert_leaf_node(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value> {
        todo!()
    }

    fn get_leaf(&self, key: &Self::Key) -> Self::Leaf {
        todo!()
    }

    fn hash_leaf(leaf: &Self::Leaf) -> RpoDigest {
        todo!()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum NewSmtLeaf {
    Single((u64, Word)),
    Multiple(Vec<(u64, Word)>),
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
