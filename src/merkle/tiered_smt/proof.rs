use super::{BTreeMap, CanonicalWord, EmptyNodesSubtrees, MerklePath, TieredSmt, Word};

// LEAF PROOF
// ================================================================================================

/// Encapsulates the arguments to prove the membership of a leaf for a given tiered tree root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafProof {
    pub input: LeafProofInput,
    pub path: MerklePath,
}

impl LeafProof {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of a membership proof.
    pub fn new(input: LeafProofInput, path: MerklePath) -> Self {
        Self { input, path }
    }

    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Verifies the membership of the key-value pair for the given Merkle root of a `[TieredSmt]`.
    pub fn verify_membership(&self, key: &Word, value: Word, root: &Word) -> bool {
        let key = CanonicalWord::from(key);

        // compute the target index.
        let depth = self.path.depth();
        let index = TieredSmt::index_from_key(&key, depth);

        // compute the input of the merkle opening.
        let node = match &self.input {
            LeafProofInput::Lower(leaves) => {
                if !leaves.contains_key(&key) {
                    return false;
                }
                TieredSmt::hash_bottom_leaves(leaves)
            }
            _ => TieredSmt::hash_upper_leaf(key.into(), value.into(), index.depth()),
        };

        // execute the merkle opening verification.
        self.path.verify(index.value(), node.into(), root)
    }

    /// Verifies the non-membership of the key-value pair for the given Merkle root of a
    /// `[TieredSmt]`.
    pub fn verify_non_membership(&self, key: &Word, value: Word, root: &Word) -> bool {
        let key = CanonicalWord::from(key);

        // compute the depth of the proof.
        let depth = self.path.len() as u8;
        let index = TieredSmt::index_from_key(&key, depth);

        // compute the input of the merkle opening.
        let node = match &self.input {
            LeafProofInput::Empty => EmptyNodesSubtrees::get_node_64(depth),
            LeafProofInput::Lower(leaves) => {
                if leaves.contains_key(&key) {
                    return false;
                }
                TieredSmt::hash_bottom_leaves(leaves)
            }
            LeafProofInput::Upper(k, v) => {
                if k == &key && v == &value {
                    return false;
                }
                TieredSmt::hash_upper_leaf((*k).into(), (*v).into(), index.depth())
            }
        };

        // execute the merkle opening verification.
        self.path.verify(index.value(), node.into(), root)
    }
}

// LEAF PROOF INPUT
// ================================================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafProofInput {
    Empty,
    Lower(BTreeMap<CanonicalWord, Word>),
    Upper(CanonicalWord, Word),
}

impl Default for LeafProofInput {
    fn default() -> Self {
        Self::Empty
    }
}
