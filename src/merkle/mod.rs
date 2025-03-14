//! Data structures related to Merkle trees based on RPO256 hash function.

use super::{
    EMPTY_WORD, Felt, Word, ZERO,
    hash::rpo::{Rpo256, RpoDigest},
};

// REEXPORTS
// ================================================================================================

mod empty_roots;
pub use empty_roots::EmptySubtreeRoots;

mod index;
pub use index::NodeIndex;

mod merkle_tree;
pub use merkle_tree::{MerkleTree, path_to_text, tree_to_text};

mod path;
pub use path::{MerklePath, RootPath, ValuePath};

mod smt;
pub use smt::{
    InnerNode, LeafIndex, MutationSet, NodeMutation, PartialSmt, SMT_DEPTH, SMT_MAX_DEPTH,
    SMT_MIN_DEPTH, SimpleSmt, Smt, SmtLeaf, SmtLeafError, SmtProof, SmtProofError,
};
#[cfg(feature = "internal")]
pub use smt::{SubtreeLeaf, build_subtree_for_bench};

mod mmr;
pub use mmr::{InOrderIndex, Mmr, MmrDelta, MmrError, MmrPeaks, MmrProof, PartialMmr};

mod store;
pub use store::{DefaultMerkleStore, MerkleStore, RecordingMerkleStore, StoreNode};

mod node;
pub use node::InnerNodeInfo;

mod partial_mt;
pub use partial_mt::PartialMerkleTree;

mod error;
pub use error::MerkleError;

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
fn digests_to_words(digests: &[RpoDigest]) -> alloc::vec::Vec<Word> {
    digests.iter().map(|d| d.into()).collect()
}
