use crate::{
    merkle::{MerklePath, NodeIndex, RpoDigest},
    utils::collections::Vec,
};
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MerkleError {
    ConflictingRoots(Vec<RpoDigest>),
    DepthTooSmall(u8),
    DepthTooBig(u64),
    DuplicateValuesForIndex(u64),
    DuplicateValuesForKey(RpoDigest),
    InvalidIndex { depth: u8, value: u64 },
    InvalidDepth { expected: u8, provided: u8 },
    InvalidPath(MerklePath),
    InvalidNumEntries(usize),
    NodeNotInSet(NodeIndex),
    NodeNotInStore(RpoDigest, NodeIndex),
    NumLeavesNotPowerOfTwo(usize),
    RootNotInStore(RpoDigest),
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MerkleError::*;
        match self {
            ConflictingRoots(roots) => write!(f, "the merkle paths roots do not match {roots:?}"),
            DepthTooSmall(depth) => write!(f, "the provided depth {depth} is too small"),
            DepthTooBig(depth) => write!(f, "the provided depth {depth} is too big"),
            DuplicateValuesForIndex(key) => write!(f, "multiple values provided for key {key}"),
            DuplicateValuesForKey(key) => write!(f, "multiple values provided for key {key}"),
            InvalidIndex { depth, value } => {
                write!(f, "the index value {value} is not valid for the depth {depth}")
            }
            InvalidDepth { expected, provided } => {
                write!(f, "the provided depth {provided} is not valid for {expected}")
            }
            InvalidPath(_path) => write!(f, "the provided path is not valid"),
            InvalidNumEntries(max) => write!(f, "number of entries exceeded the maximum: {max}"),
            NodeNotInSet(index) => write!(f, "the node with index ({index}) is not in the set"),
            NodeNotInStore(hash, index) => {
                write!(f, "the node {hash:?} with index ({index}) is not in the store")
            }
            NumLeavesNotPowerOfTwo(leaves) => {
                write!(f, "the leaves count {leaves} is not a power of 2")
            }
            RootNotInStore(root) => write!(f, "the root {:?} is not in the store", root),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MerkleError {}
