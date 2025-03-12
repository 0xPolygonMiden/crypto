use thiserror::Error;

use crate::{
    hash::rpo::RpoDigest,
    merkle::{LeafIndex, SMT_DEPTH},
};

// SMT LEAF ERROR
// =================================================================================================

#[derive(Debug, Error)]
pub enum SmtLeafError {
    #[error(
      "multiple leaf requires all keys to map to the same leaf index but key1 {key_1} and key2 {key_2} map to different indices"
    )]
    InconsistentMultipleLeafKeys { key_1: RpoDigest, key_2: RpoDigest },
    #[error("single leaf key {key} maps to {actual_leaf_index:?} but was expected to map to {expected_leaf_index:?}")]
    InconsistentSingleLeafIndices {
        key: RpoDigest,
        expected_leaf_index: LeafIndex<SMT_DEPTH>,
        actual_leaf_index: LeafIndex<SMT_DEPTH>,
    },
    #[error("supplied leaf index {leaf_index_supplied:?} does not match {leaf_index_from_keys:?} for multiple leaf")]
    InconsistentMultipleLeafIndices {
        leaf_index_from_keys: LeafIndex<SMT_DEPTH>,
        leaf_index_supplied: LeafIndex<SMT_DEPTH>,
    },
    #[error("multiple leaf requires at least two entries but only {0} were given")]
    MultipleLeafRequiresTwoEntries(usize),
}

// SMT PROOF ERROR
// =================================================================================================

#[derive(Debug, Error)]
pub enum SmtProofError {
    #[error("merkle path length {0} does not match SMT depth {SMT_DEPTH}")]
    InvalidMerklePathLength(usize),
}
