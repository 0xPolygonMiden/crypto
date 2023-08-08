use crate::hash::rpo::RpoDigest;

/// Representation of a node with two children used for iterating over containers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct InnerNodeInfo {
    pub value: RpoDigest,
    pub left: RpoDigest,
    pub right: RpoDigest,
}
