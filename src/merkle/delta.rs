use super::{
    BTreeMap, KvMap, MerkleError, MerkleStore, NodeIndex, RpoDigest, StoreNode, Vec, Word,
};
use crate::utils::collections::Diff;

#[cfg(test)]
use super::{super::ONE, Felt, SimpleSmt, EMPTY_WORD, ZERO};

// MERKLE STORE DELTA
// ================================================================================================

/// [MerkleStoreDelta] stores a vector of ([RpoDigest], [MerkleTreeDelta]) tuples where the
/// [RpoDigest] represents the root of the Merkle tree and [MerkleTreeDelta] represents the
/// differences between the initial and final Merkle tree states.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MerkleStoreDelta(pub Vec<(RpoDigest, MerkleTreeDelta)>);

// MERKLE TREE DELTA
// ================================================================================================

/// [MerkleDelta] stores the differences between the initial and final Merkle tree states.
///
/// The differences are represented as follows:
/// - depth: the depth of the merkle tree.
/// - cleared_slots: indexes of slots where values were set to [ZERO; 4].
/// - updated_slots: index-value pairs of slots where values were set to non [ZERO; 4] values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MerkleTreeDelta {
    depth: u8,
    cleared_slots: Vec<u64>,
    updated_slots: Vec<(u64, Word)>,
}

impl MerkleTreeDelta {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    pub fn new(depth: u8) -> Self {
        Self {
            depth,
            cleared_slots: Vec::new(),
            updated_slots: Vec::new(),
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------
    /// Returns the depth of the Merkle tree the [MerkleDelta] is associated with.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns the indexes of slots where values were set to [ZERO; 4].
    pub fn cleared_slots(&self) -> &[u64] {
        &self.cleared_slots
    }

    /// Returns the index-value pairs of slots where values were set to non [ZERO; 4] values.
    pub fn updated_slots(&self) -> &[(u64, Word)] {
        &self.updated_slots
    }

    // MODIFIERS
    // --------------------------------------------------------------------------------------------
    /// Adds a slot index to the list of cleared slots.
    pub fn add_cleared_slot(&mut self, index: u64) {
        self.cleared_slots.push(index);
    }

    /// Adds a slot index and a value to the list of updated slots.
    pub fn add_updated_slot(&mut self, index: u64, value: Word) {
        self.updated_slots.push((index, value));
    }
}

/// Extracts a [MerkleDelta] object by comparing the leaves of two Merkle trees specifies by
/// their roots and depth.
pub fn merkle_tree_delta<T: KvMap<RpoDigest, StoreNode>>(
    tree_root_1: RpoDigest,
    tree_root_2: RpoDigest,
    depth: u8,
    merkle_store: &MerkleStore<T>,
) -> Result<MerkleTreeDelta, MerkleError> {
    if tree_root_1 == tree_root_2 {
        return Ok(MerkleTreeDelta::new(depth));
    }

    let tree_1_leaves: BTreeMap<NodeIndex, RpoDigest> =
        merkle_store.non_empty_leaves(tree_root_1, depth).collect();
    let tree_2_leaves: BTreeMap<NodeIndex, RpoDigest> =
        merkle_store.non_empty_leaves(tree_root_2, depth).collect();
    let diff = tree_1_leaves.diff(&tree_2_leaves);

    // TODO: Refactor this diff implementation to prevent allocation of both BTree and Vec.
    Ok(MerkleTreeDelta {
        depth,
        cleared_slots: diff.removed.into_iter().map(|index| index.value()).collect(),
        updated_slots: diff
            .updated
            .into_iter()
            .map(|(index, leaf)| (index.value(), *leaf))
            .collect(),
    })
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_merkle_delta() {
        const TREE_DEPTH: u8 = 30;

        let entries = vec![
            (10, [ZERO, ONE, Felt::new(2), Felt::new(3)]),
            (15, [Felt::new(4), Felt::new(5), Felt::new(6), Felt::new(7)]),
            (20, [Felt::new(8), Felt::new(9), Felt::new(10), Felt::new(11)]),
            (31, [Felt::new(12), Felt::new(13), Felt::new(14), Felt::new(15)]),
        ];
        let simple_smt = SimpleSmt::<TREE_DEPTH>::with_leaves(entries.clone()).unwrap();
        let mut store: MerkleStore = (&simple_smt).into();
        let root = simple_smt.root();

        // add a new node
        let new_value = [Felt::new(16), Felt::new(17), Felt::new(18), Felt::new(19)];
        let new_index = NodeIndex::new(TREE_DEPTH, 32).unwrap();
        let root = store.set_node(root, new_index, new_value.into()).unwrap().root;

        // update an existing node
        let update_value = [Felt::new(20), Felt::new(21), Felt::new(22), Felt::new(23)];
        let update_idx = NodeIndex::new(TREE_DEPTH, entries[0].0).unwrap();
        let root = store.set_node(root, update_idx, update_value.into()).unwrap().root;

        // remove a node
        let remove_idx = NodeIndex::new(TREE_DEPTH, entries[1].0).unwrap();
        let root = store.set_node(root, remove_idx, EMPTY_WORD.into()).unwrap().root;

        let merkle_delta = merkle_tree_delta(simple_smt.root(), root, TREE_DEPTH, &store).unwrap();
        let expected_merkle_delta = MerkleTreeDelta {
            depth: TREE_DEPTH,
            cleared_slots: vec![remove_idx.value()],
            updated_slots: vec![(update_idx.value(), update_value), (new_index.value(), new_value)],
        };

        assert_eq!(merkle_delta, expected_merkle_delta);
    }
}
