use super::{
    hash::rpo::{Rpo256, RpoDigest},
    utils::collections::{vec, BTreeMap, Vec},
    Felt, StarkField, Word, WORD_SIZE, ZERO,
};
use core::fmt;

mod merkle_tree;
pub use merkle_tree::MerkleTree;

mod merkle_path_set;
pub use merkle_path_set::MerklePathSet;

mod simple_smt;
pub use simple_smt::SimpleSmt;

mod tiered_smt;
pub use tiered_smt::TieredSmt;

// ERRORS
// ================================================================================================

#[derive(Clone, Debug)]
pub enum MerkleError {
    DepthTooSmall(u32),
    DepthTooBig(u32),
    NumLeavesNotPowerOfTwo(usize),
    InvalidIndex(u32, u64),
    InvalidDepth(u32, u32),
    InvalidPath(Vec<Word>),
    InvalidEntriesCount(usize, usize),
    NodeNotInSet(u64),
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MerkleError::*;
        match self {
            DepthTooSmall(depth) => write!(f, "the provided depth {depth} is too small"),
            DepthTooBig(depth) => write!(f, "the provided depth {depth} is too big"),
            NumLeavesNotPowerOfTwo(leaves) => {
                write!(f, "the leaves count {leaves} is not a power of 2")
            }
            InvalidIndex(depth, index) => write!(
                f,
                "the leaf index {index} is not valid for the depth {depth}"
            ),
            InvalidDepth(expected, provided) => write!(
                f,
                "the provided depth {provided} is not valid for {expected}"
            ),
            InvalidPath(_path) => write!(f, "the provided path is not valid"),
            InvalidEntriesCount(max, provided) => write!(f, "the provided number of entries is {provided}, but the maximum for the given depth is {max}"),
            NodeNotInSet(index) => write!(f, "the node indexed by {index} is not in the set"),
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

/// Computes a set of sub-trees of an empty merkle tree.
///
/// The returned vector is indexed by the depth and will contain the correspondent hash.
fn empty_merkle_subtrees<T>(depth: u8) -> Vec<T>
where
    T: From<RpoDigest>,
{
    (0..depth as u16 + 1)
        .scan(RpoDigest::default(), |state, _| {
            let value = *state;
            *state = Rpo256::merge(&[value, value]);
            Some(value)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(T::from)
        .collect()
}

#[test]
fn empty_merkle_subtrees_is_calculated_correctly() {
    let null = empty_merkle_subtrees(u8::MAX);
    let mut root = RpoDigest::default();
    for _ in 0..u8::MAX {
        root = Rpo256::merge(&[root, root]);
    }
    assert_eq!(root, null[0]);
}
