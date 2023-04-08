use super::Word;

/// Representation of a node with two children used for iterating over containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerNodeInfo {
    pub value: Word,
    pub left: Word,
    pub right: Word,
}
