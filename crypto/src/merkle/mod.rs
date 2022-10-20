use crate::{Felt, FieldElement, Word};

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
