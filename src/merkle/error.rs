use thiserror::Error;

use super::{NodeIndex, RpoDigest};

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("expected merkle root {expected_root} found {actual_root}")]
    ConflictingRoots {
        expected_root: RpoDigest,
        actual_root: RpoDigest,
    },
    #[error("provided merkle tree depth {0} is too small")]
    DepthTooSmall(u8),
    #[error("provided merkle tree depth {0} is too big")]
    DepthTooBig(u64),
    #[error("multiple values provided for merkle tree index {0}")]
    DuplicateValuesForIndex(u64),
    #[error("node index value {value} is not valid for depth {depth}")]
    InvalidNodeIndex { depth: u8, value: u64 },
    #[error("provided node index depth {provided} does not match expected depth {expected}")]
    InvalidNodeIndexDepth { expected: u8, provided: u8 },
    #[error("merkle subtree depth {subtree_depth} exceeds merkle tree depth {tree_depth}")]
    SubtreeDepthExceedsDepth { subtree_depth: u8, tree_depth: u8 },
    #[error("number of entries in the merkle tree exceeds the maximum of {0}")]
    TooManyEntries(usize),
    #[error("node index `{0}` not found in the tree")]
    NodeIndexNotFoundInTree(NodeIndex),
    #[error("node {0:?} with index `{1}` not found in the store")]
    NodeIndexNotFoundInStore(RpoDigest, NodeIndex),
    #[error("number of provided merkle tree leaves {0} is not a power of two")]
    NumLeavesNotPowerOfTwo(usize),
    #[error("root {0:?} is not in the store")]
    RootNotInStore(RpoDigest),
    #[error(
        "partial smt does not track the merkle path for key {0} so updating it would produce a different root compared to the same update in the full tree"
    )]
    UntrackedKey(RpoDigest),
}
