use super::{
    hash::rpo::{Rpo256, RpoDigest},
    utils::collections::{vec, BTreeMap, BTreeSet, Vec},
    Felt, StarkField, Word, WORD_SIZE, ZERO,
};
use core::fmt;

// REEXPORTS
// ================================================================================================

mod empty_roots;
pub use empty_roots::EmptySubtreeRoots;

mod index;
pub use index::NodeIndex;

mod merkle_tree;
pub use merkle_tree::{path_to_text, tree_to_text, MerkleTree};

mod path;
pub use path::{MerklePath, RootPath, ValuePath};

mod path_set;
pub use path_set::MerklePathSet;

mod simple_smt;
pub use simple_smt::SimpleSmt;

mod tiered_smt;
pub use tiered_smt::TieredSmt;

mod mmr;
pub use mmr::{Mmr, MmrPeaks, MmrProof};

mod store;
pub use store::MerkleStore;

mod node;
pub use node::InnerNodeInfo;

mod partial_mt;
pub use partial_mt::PartialMerkleTree;

// ERRORS
// ================================================================================================

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
    InvalidNumEntries(usize, usize),
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
            InvalidIndex{ depth, value} => write!(
                f,
                "the index value {value} is not valid for the depth {depth}"
            ),
            InvalidDepth { expected, provided } => write!(
                f,
                "the provided depth {provided} is not valid for {expected}"
            ),
            InvalidPath(_path) => write!(f, "the provided path is not valid"),
            InvalidNumEntries(max, provided) => write!(f, "the provided number of entries is {provided}, but the maximum for the given depth is {max}"),
            NodeNotInSet(index) => write!(f, "the node with index ({index}) is not in the set"),
            NodeNotInStore(hash, index) => write!(f, "the node {hash:?} with index ({index}) is not in the store"),
            NumLeavesNotPowerOfTwo(leaves) => {
                write!(f, "the leaves count {leaves} is not a power of 2")
            }
            RootNotInStore(root) => write!(f, "the root {:?} is not in the store", root),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MerkleError {}

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
const fn int_to_node(value: u64) -> RpoDigest {
    RpoDigest::new([Felt::new(value), ZERO, ZERO, ZERO])
}

#[cfg(test)]
const fn int_to_leaf(value: u64) -> Word {
    [Felt::new(value), ZERO, ZERO, ZERO]
}

#[cfg(test)]
fn digests_to_words(digests: &[RpoDigest]) -> Vec<Word> {
    digests.iter().map(|d| d.into()).collect()
}
