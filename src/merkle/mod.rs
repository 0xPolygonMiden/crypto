//! Data structures related to Merkle trees based on RPO256 hash function.

use super::{
    hash::rpo::{Rpo256, RpoDigest},
    utils::collections::{vec, BTreeMap, BTreeSet, KvMap, RecordingMap, TryApplyDiff, Vec},
    Felt, StarkField, Word, EMPTY_WORD, ZERO,
};

// REEXPORTS
// ================================================================================================

mod empty_roots;
pub use empty_roots::EmptySubtreeRoots;

mod delta;
pub use delta::{merkle_tree_delta, MerkleStoreDelta, MerkleTreeDelta};

mod index;
pub use index::NodeIndex;

mod merkle_tree;
pub use merkle_tree::{path_to_text, tree_to_text, MerkleTree};

mod path;
pub use path::{MerklePath, RootPath, ValuePath};

mod simple_smt;
pub use simple_smt::{SimpleSmt, SMT_MIN_DEPTH};

mod smt;
pub use smt::{InnerNode, LeafIndex, SparseMerkleTree, SMT_MAX_DEPTH};

mod new_smt;
pub use new_smt::{NewSmt, NewSmtKey, NewSmtLeaf, NEW_SMT_DEPTH};

mod tiered_smt;
pub use tiered_smt::{TieredSmt, TieredSmtProof, TieredSmtProofError};

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
fn digests_to_words(digests: &[RpoDigest]) -> Vec<Word> {
    digests.iter().map(|d| d.into()).collect()
}
