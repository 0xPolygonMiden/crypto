use crate::{Felt, Word, ZERO};

pub mod merkle_path_set;
pub mod merkle_tree;

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
