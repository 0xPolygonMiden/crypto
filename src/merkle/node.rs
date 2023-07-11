use crate::hash::rpo::RpoDigest;

/// Representation of a node with two children used for iterating over containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerNodeInfo {
    pub value: RpoDigest,
    pub left: RpoDigest,
    pub right: RpoDigest,
}
