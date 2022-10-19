pub mod merkle_path_set;
pub mod merkle_tree;

use winterfell::crypto::Hasher as HashFn;

pub use winterfell::crypto::hashers::Rp64_256 as Hasher;
pub use winterfell::math::{
    fields::{f64::BaseElement as Felt, QuadExtension},
    ExtensionOf, FieldElement, StarkField,
};

// TYPE ALIASES
// ================================================================================================

pub type Word = [Felt; 4];
pub type Digest = <Hasher as HashFn>::Digest;

// PASS-THROUGH FUNCTIONS
// ================================================================================================

/// Returns a hash of two digests. This method is intended for use in construction of Merkle trees.
#[inline(always)]
pub fn merge(values: &[Digest; 2]) -> Digest {
    Hasher::merge(values)
}

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

// UTILITY FUNCTIONS
// ================================================================================================
