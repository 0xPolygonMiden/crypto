use super::{
    hash::rpo::{Rpo256, RpoDigest as Digest},
    utils::collections::{BTreeMap, Vec},
    Felt, Word, ZERO,
};

mod merkle_tree;
pub use merkle_tree::MerkleTree;

mod merkle_path_set;
pub use merkle_path_set::MerklePathSet;

// ERRORS
// ================================================================================================

#[derive(Clone, Debug)]
pub enum MerkleError {
    DepthTooSmall,
    DepthTooBig(u32),
    NumLeavesNotPowerOfTwo(usize),
    InvalidIndex(u32, u64),
    InvalidDepth(u32, u32),
    InvalidPath(Vec<Word>),
    NodeNotInSet(u64),
}

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
const fn int_to_node(value: u64) -> Word {
    [Felt::new(value), ZERO, ZERO, ZERO]
}
