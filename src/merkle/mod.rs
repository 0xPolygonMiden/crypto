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

mod mmr;
pub use mmr::{Mmr, MmrPeaks};

mod store;
pub use store::MerkleStore;

// ERRORS
// ================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MerkleError {
    ConflictingRoots(Vec<Word>),
    DepthTooSmall(u8),
    DepthTooBig(u64),
    NodeNotInStore(Word, NodeIndex),
    NumLeavesNotPowerOfTwo(usize),
    InvalidIndex(NodeIndex),
    InvalidDepth { expected: u8, provided: u8 },
    InvalidPath(MerklePath),
    InvalidEntriesCount(usize, usize),
    NodeNotInSet(u64),
    RootNotInStore(Word),
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MerkleError::*;
        match self {
            ConflictingRoots(roots) => write!(f, "the merkle paths roots do not match {roots:?}"),
            DepthTooSmall(depth) => write!(f, "the provided depth {depth} is too small"),
            DepthTooBig(depth) => write!(f, "the provided depth {depth} is too big"),
            NumLeavesNotPowerOfTwo(leaves) => {
                write!(f, "the leaves count {leaves} is not a power of 2")
            }
            InvalidIndex(index) => write!(
                f,
                "the index value {} is not valid for the depth {}", index.value(), index.depth()
            ),
            InvalidDepth { expected, provided } => write!(
                f,
                "the provided depth {provided} is not valid for {expected}"
            ),
            InvalidPath(_path) => write!(f, "the provided path is not valid"),
            InvalidEntriesCount(max, provided) => write!(f, "the provided number of entries is {provided}, but the maximum for the given depth is {max}"),
            NodeNotInSet(index) => write!(f, "the node indexed by {index} is not in the set"),
            NodeNotInStore(hash, index) => write!(f, "the node {:?} indexed by {} and depth {} is not in the store", hash, index.value(), index.depth(),),
            RootNotInStore(root) => write!(f, "the root {:?} is not in the store", root),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MerkleError {}

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
const fn int_to_node(value: u64) -> Word {
    [Felt::new(value), ZERO, ZERO, ZERO]
}
