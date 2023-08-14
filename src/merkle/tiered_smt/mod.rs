use super::{
    BTreeMap, BTreeSet, EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, NodeIndex,
    Rpo256, RpoDigest, StarkField, Vec, Word,
};
use crate::utils::vec;
use core::{cmp, ops::Deref};

mod nodes;
use nodes::NodeStore;

mod values;
use values::ValueStore;

mod proof;
pub use proof::TieredSmtProof;

mod error;
pub use error::TieredSmtProofError;

#[cfg(test)]
mod tests;

// TIERED SPARSE MERKLE TREE
// ================================================================================================

/// Tiered (compacted) Sparse Merkle tree mapping 256-bit keys to 256-bit values. Both keys and
/// values are represented by 4 field elements.
///
/// Leaves in the tree can exist only on specific depths called "tiers". These depths are: 16, 32,
/// 48, and 64. Initially, when a tree is empty, it is equivalent to an empty Sparse Merkle tree
/// of depth 64 (i.e., leaves at depth 64 are set to [ZERO; 4]). As non-empty values are inserted
/// into the tree they are added to the first available tier.
///
/// For example, when the first key-value pair is inserted, it will be stored in a node at depth
/// 16 such that the 16 most significant bits of the key determine the position of the node at
/// depth 16. If another value with a key sharing the same 16-bit prefix is inserted, both values
/// move into the next tier (depth 32). This process is repeated until values end up at the bottom
/// tier (depth 64). If multiple values have keys with a common 64-bit prefix, such key-value pairs
/// are stored in a sorted list at the bottom tier.
///
/// To differentiate between internal and leaf nodes, node values are computed as follows:
/// - Internal nodes: hash(left_child, right_child).
/// - Leaf node at depths 16, 32, or 64: hash(key, value, domain=depth).
/// - Leaf node at depth 64: hash([key_0, value_0, ..., key_n, value_n], domain=64).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TieredSmt {
    root: RpoDigest,
    nodes: NodeStore,
    values: ValueStore,
}

impl TieredSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of levels between tiers.
    const TIER_SIZE: u8 = 16;

    /// Depths at which leaves can exist in a tiered SMT.
    const TIER_DEPTHS: [u8; 4] = [16, 32, 48, 64];

    /// Maximum node depth. This is also the bottom tier of the tree.
    const MAX_DEPTH: u8 = 64;

    /// Value of an empty leaf.
    pub const EMPTY_VALUE: Word = super::empty_roots::EMPTY_WORD;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [TieredSmt] instantiated with the specified key-value pairs.
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    pub fn with_leaves<R, I>(entries: R) -> Result<Self, MerkleError>
    where
        R: IntoIterator<IntoIter = I>,
        I: Iterator<Item = (RpoDigest, Word)> + ExactSizeIterator,
    {
        // create an empty tree
        let mut tree = Self::default();

        // append leaves to the tree returning an error if a duplicate entry for the same key
        // is found
        let mut empty_entries = BTreeSet::new();
        for (key, value) in entries {
            let old_value = tree.insert(key, value);
            if old_value != Self::EMPTY_VALUE || empty_entries.contains(&key) {
                return Err(MerkleError::DuplicateValuesForKey(key));
            }
            // if we've processed an empty entry, add the key to the set of empty entry keys, and
            // if this key was already in the set, return an error
            if value == Self::EMPTY_VALUE && !empty_entries.insert(key) {
                return Err(MerkleError::DuplicateValuesForKey(key));
            }
        }
        Ok(tree)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of this Merkle tree.
    pub const fn root(&self) -> RpoDigest {
        self.root
    }

    /// Returns a node at the specified index.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The specified index depth is 0 or greater than 64.
    /// - The node with the specified index does not exists in the Merkle tree. This is possible
    ///   when a leaf node with the same index prefix exists at a tier higher than the requested
    ///   node.
    pub fn get_node(&self, index: NodeIndex) -> Result<RpoDigest, MerkleError> {
        self.nodes.get_node(index)
    }

    /// Returns a Merkle path from the node at the specified index to the root.
    ///
    /// The node itself is not included in the path.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The specified index depth is 0 or greater than 64.
    /// - The node with the specified index does not exists in the Merkle tree. This is possible
    ///   when a leaf node with the same index prefix exists at a tier higher than the node to
    ///   which the path is requested.
    pub fn get_path(&self, index: NodeIndex) -> Result<MerklePath, MerkleError> {
        self.nodes.get_path(index)
    }

    /// Returns the value associated with the specified key.
    ///
    /// If nothing was inserted into this tree for the specified key, [ZERO; 4] is returned.
    pub fn get_value(&self, key: RpoDigest) -> Word {
        match self.values.get(&key) {
            Some(value) => *value,
            None => Self::EMPTY_VALUE,
        }
    }

    /// Returns a proof for a key-value pair defined by the specified key.
    ///
    /// The proof can be used to attest membership of this key-value pair in a Tiered Sparse Merkle
    /// Tree defined by the same root as this tree.
    pub fn prove(&self, key: RpoDigest) -> TieredSmtProof {
        let (path, index, leaf_exists) = self.nodes.get_proof(&key);

        let entries = if index.depth() == Self::MAX_DEPTH {
            match self.values.get_all(index.value()) {
                Some(entries) => entries,
                None => vec![(key, Self::EMPTY_VALUE)],
            }
        } else if leaf_exists {
            let entry =
                self.values.get_first(index_to_prefix(&index)).expect("leaf entry not found");
            debug_assert_eq!(entry.0, key);
            vec![*entry]
        } else {
            vec![(key, Self::EMPTY_VALUE)]
        };

        TieredSmtProof::new(path, entries).expect("Bug detected, TSMT produced invalid proof")
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts the provided value into the tree under the specified key and returns the value
    /// previously stored under this key.
    ///
    /// If the value for the specified key was not previously set, [ZERO; 4] is returned.
    pub fn insert(&mut self, key: RpoDigest, value: Word) -> Word {
        // if an empty value is being inserted, remove the leaf node to make it look as if the
        // value was never inserted
        if value == Self::EMPTY_VALUE {
            return self.remove_leaf_node(key);
        }

        // insert the value into the value store, and if the key was already in the store, update
        // it with the new value
        if let Some(old_value) = self.values.insert(key, value) {
            if old_value != value {
                // if the new value is different from the old value, determine the location of
                // the leaf node for this key, build the node, and update the root
                let (index, leaf_exists) = self.nodes.get_leaf_index(&key);
                debug_assert!(leaf_exists);
                let node = self.build_leaf_node(index, key, value);
                self.root = self.nodes.update_leaf_node(index, node);
            }
            return old_value;
        };

        // determine the location for the leaf node; this index could have 3 different meanings:
        // - it points to a root of an empty subtree or an empty node at depth 64; in this case,
        //   we can replace the node with the value node immediately.
        // - it points to an existing leaf at the bottom tier (i.e., depth = 64); in this case,
        //   we need to process update the bottom leaf.
        // - it points to an existing leaf node for a different key with the same prefix (same
        //   key case was handled above); in this case, we need to move the leaf to a lower tier
        let (index, leaf_exists) = self.nodes.get_leaf_index(&key);

        self.root = if leaf_exists && index.depth() == Self::MAX_DEPTH {
            // returned index points to a leaf at the bottom tier
            let node = self.build_leaf_node(index, key, value);
            self.nodes.update_leaf_node(index, node)
        } else if leaf_exists {
            // returned index pointes to a leaf for a different key with the same prefix

            // get the key-value pair for the key with the same prefix; since the key-value
            // pair has already been inserted into the value store, we need to filter it out
            // when looking for the other key-value pair
            let (other_key, other_value) = self
                .values
                .get_first_filtered(index_to_prefix(&index), &key)
                .expect("other key-value pair not found");

            // determine how far down the tree should we move the leaves
            let common_prefix_len = get_common_prefix_tier_depth(&key, other_key);
            let depth = cmp::min(common_prefix_len + Self::TIER_SIZE, Self::MAX_DEPTH);

            // compute node locations for new and existing key-value paris
            let new_index = LeafNodeIndex::from_key(&key, depth);
            let other_index = LeafNodeIndex::from_key(other_key, depth);

            // compute node values for the new and existing key-value pairs
            let new_node = self.build_leaf_node(new_index, key, value);
            let other_node = self.build_leaf_node(other_index, *other_key, *other_value);

            // replace the leaf located at index with a subtree containing nodes for new and
            // existing key-value paris
            self.nodes.replace_leaf_with_subtree(
                index,
                [(new_index, new_node), (other_index, other_node)],
            )
        } else {
            // returned index points to an empty subtree or an empty leaf at the bottom tier
            let node = self.build_leaf_node(index, key, value);
            self.nodes.insert_leaf_node(index, node)
        };

        Self::EMPTY_VALUE
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over all key-value pairs in this [TieredSmt].
    pub fn iter(&self) -> impl Iterator<Item = &(RpoDigest, Word)> {
        self.values.iter()
    }

    /// Returns an iterator over all inner nodes of this [TieredSmt] (i.e., nodes not at depths 16
    /// 32, 48, or 64).
    ///
    /// The iterator order is unspecified.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.nodes.inner_nodes()
    }

    /// Returns an iterator over upper leaves (i.e., depth = 16, 32, or 48) for this [TieredSmt]
    /// where each yielded item is a (node, key, value) tuple.
    ///
    /// The iterator order is unspecified.
    pub fn upper_leaves(&self) -> impl Iterator<Item = (RpoDigest, RpoDigest, Word)> + '_ {
        self.nodes.upper_leaves().map(|(index, node)| {
            let key_prefix = index_to_prefix(index);
            let (key, value) = self.values.get_first(key_prefix).expect("upper leaf not found");
            debug_assert_eq!(*index, LeafNodeIndex::from_key(key, index.depth()).into());
            (*node, *key, *value)
        })
    }

    /// Returns an iterator over upper leaves (i.e., depth = 16, 32, or 48) for this [TieredSmt]
    /// where each yielded item is a (node_index, value) tuple.
    pub fn upper_leaf_nodes(&self) -> impl Iterator<Item = (&NodeIndex, &RpoDigest)> {
        self.nodes.upper_leaves()
    }

    /// Returns an iterator over bottom leaves (i.e., depth = 64) of this [TieredSmt].
    ///
    /// Each yielded item consists of the hash of the leaf and its contents, where contents is
    /// a vector containing key-value pairs of entries storied in this leaf.
    ///
    /// The iterator order is unspecified.
    pub fn bottom_leaves(&self) -> impl Iterator<Item = (RpoDigest, Vec<(RpoDigest, Word)>)> + '_ {
        self.nodes.bottom_leaves().map(|(&prefix, node)| {
            let values = self.values.get_all(prefix).expect("bottom leaf not found");
            (*node, values)
        })
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Removes the node holding the key-value pair for the specified key from this tree, and
    /// returns the value associated with the specified key.
    ///
    /// If no value was associated with the specified key, [ZERO; 4] is returned.
    fn remove_leaf_node(&mut self, key: RpoDigest) -> Word {
        // remove the key-value pair from the value store; if no value was associated with the
        // specified key, return.
        let old_value = match self.values.remove(&key) {
            Some(old_value) => old_value,
            None => return Self::EMPTY_VALUE,
        };

        // determine the location of the leaf holding the key-value pair to be removed
        let (index, leaf_exists) = self.nodes.get_leaf_index(&key);
        debug_assert!(leaf_exists);

        // if the leaf is at the bottom tier and after removing the key-value pair from it, the
        // leaf is still not empty, we either just update it, or move it up to a higher tier (if
        // the leaf doesn't have siblings at lower tiers)
        if index.depth() == Self::MAX_DEPTH {
            if let Some(entries) = self.values.get_all(index.value()) {
                // if there is only one key-value pair left at the bottom leaf, and it can be
                // moved up to a higher tier, truncate the branch and return
                if entries.len() == 1 {
                    let new_depth = self.nodes.get_last_single_child_parent_depth(index.value());
                    if new_depth != Self::MAX_DEPTH {
                        let node = hash_upper_leaf(entries[0].0, entries[0].1, new_depth);
                        self.root = self.nodes.truncate_branch(index.value(), new_depth, node);
                        return old_value;
                    }
                }

                // otherwise just recompute the leaf hash and update the leaf node
                let node = hash_bottom_leaf(&entries);
                self.root = self.nodes.update_leaf_node(index, node);
                return old_value;
            };
        }

        // if the removed key-value pair has a lone sibling at the current tier with a root at
        // higher tier, we need to move the sibling to a higher tier
        if let Some((sib_key, sib_val, new_sib_index)) = self.values.get_lone_sibling(index) {
            // determine the current index of the sibling node
            let sib_index = LeafNodeIndex::from_key(sib_key, index.depth());
            debug_assert!(sib_index.depth() > new_sib_index.depth());

            // compute node value for the new location of the sibling leaf and replace the subtree
            // with this leaf node
            let node = self.build_leaf_node(new_sib_index, *sib_key, *sib_val);
            let new_sib_depth = new_sib_index.depth();
            self.root = self.nodes.replace_subtree_with_leaf(index, sib_index, new_sib_depth, node);
        } else {
            // if the removed key-value pair did not have a sibling at the current tier with a
            // root at higher tiers, just clear the leaf node
            self.root = self.nodes.clear_leaf_node(index);
        }

        old_value
    }

    /// Builds and returns a leaf node value for the node located as the specified index.
    ///
    /// This method assumes that the key-value pair for the node has already been inserted into
    /// the value store, however, for depths 16, 32, and 48, the node is computed directly from
    /// the passed-in values (for depth 64, the value store is queried to get all the key-value
    /// pairs located at the specified index).
    fn build_leaf_node(&self, index: LeafNodeIndex, key: RpoDigest, value: Word) -> RpoDigest {
        let depth = index.depth();

        // insert the key into index-key map and compute the new value of the node
        if index.depth() == Self::MAX_DEPTH {
            // for the bottom tier, we add the key-value pair to the existing leaf, or create a
            // new leaf with this key-value pair
            let values = self.values.get_all(index.value()).unwrap();
            hash_bottom_leaf(&values)
        } else {
            debug_assert_eq!(self.values.get_first(index_to_prefix(&index)), Some(&(key, value)));
            hash_upper_leaf(key, value, depth)
        }
    }
}

impl Default for TieredSmt {
    fn default() -> Self {
        let root = EmptySubtreeRoots::empty_hashes(Self::MAX_DEPTH)[0];
        Self {
            root,
            nodes: NodeStore::new(root),
            values: ValueStore::default(),
        }
    }
}

// LEAF NODE INDEX
// ================================================================================================
/// A wrapper around [NodeIndex] to provide type-safe references to nodes at depths 16, 32, 48, and
/// 64.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct LeafNodeIndex(NodeIndex);

impl LeafNodeIndex {
    /// Returns a new [LeafNodeIndex] instantiated from the provided [NodeIndex].
    ///
    /// In debug mode, panics if index depth is not 16, 32, 48, or 64.
    pub fn new(index: NodeIndex) -> Self {
        // check if the depth is 16, 32, 48, or 64; this works because for a valid depth,
        // depth - 16, can be 0, 16, 32, or 48 - i.e., the value is either 0 or any of the 4th
        // or 5th bits are set. We can test for this by computing a bitwise AND with a value
        // which has all but the 4th and 5th bits set (which is !48).
        debug_assert_eq!(((index.depth() - 16) & !48), 0, "invalid tier depth {}", index.depth());
        Self(index)
    }

    /// Returns a new [LeafNodeIndex] instantiated from the specified key inserted at the specified
    /// depth.
    ///
    /// The value for the key is computed by taking n most significant bits from the most significant
    /// element of the key, where n is the specified depth.
    pub fn from_key(key: &RpoDigest, depth: u8) -> Self {
        let mse = get_key_prefix(key);
        Self::new(NodeIndex::new_unchecked(depth, mse >> (TieredSmt::MAX_DEPTH - depth)))
    }

    /// Returns a new [LeafNodeIndex] instantiated for testing purposes.
    #[cfg(test)]
    pub fn make(depth: u8, value: u64) -> Self {
        Self::new(NodeIndex::make(depth, value))
    }

    /// Traverses towards the root until the specified depth is reached.
    ///
    /// The new depth must be a valid tier depth - i.e., 16, 32, 48, or 64.
    pub fn move_up_to(&mut self, depth: u8) {
        debug_assert_eq!(((depth - 16) & !48), 0, "invalid tier depth: {depth}");
        self.0.move_up_to(depth);
    }
}

impl Deref for LeafNodeIndex {
    type Target = NodeIndex;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<NodeIndex> for LeafNodeIndex {
    fn from(value: NodeIndex) -> Self {
        Self::new(value)
    }
}

impl From<LeafNodeIndex> for NodeIndex {
    fn from(value: LeafNodeIndex) -> Self {
        value.0
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the value representing the 64 most significant bits of the specified key.
fn get_key_prefix(key: &RpoDigest) -> u64 {
    Word::from(key)[3].as_int()
}

/// Returns the index value shifted to be in the most significant bit positions of the returned
/// u64 value.
fn index_to_prefix(index: &NodeIndex) -> u64 {
    index.value() << (TieredSmt::MAX_DEPTH - index.depth())
}

/// Returns tiered common prefix length between the most significant elements of the provided keys.
///
/// Specifically:
/// - returns 64 if the most significant elements are equal.
/// - returns 48 if the common prefix is between 48 and 63 bits.
/// - returns 32 if the common prefix is between 32 and 47 bits.
/// - returns 16 if the common prefix is between 16 and 31 bits.
/// - returns 0 if the common prefix is fewer than 16 bits.
fn get_common_prefix_tier_depth(key1: &RpoDigest, key2: &RpoDigest) -> u8 {
    let e1 = get_key_prefix(key1);
    let e2 = get_key_prefix(key2);
    let ex = (e1 ^ e2).leading_zeros() as u8;
    (ex / 16) * 16
}

/// Computes node value for leaves at tiers 16, 32, or 48.
///
/// Node value is computed as: hash(key || value, domain = depth).
pub fn hash_upper_leaf(key: RpoDigest, value: Word, depth: u8) -> RpoDigest {
    const NUM_UPPER_TIERS: usize = TieredSmt::TIER_DEPTHS.len() - 1;
    debug_assert!(TieredSmt::TIER_DEPTHS[..NUM_UPPER_TIERS].contains(&depth));
    Rpo256::merge_in_domain(&[key, value.into()], depth.into())
}

/// Computes node value for leaves at the bottom tier (depth 64).
///
/// Node value is computed as: hash([key_0, value_0, ..., key_n, value_n], domain=64).
///
/// TODO: when hashing in domain is implemented for `hash_elements()`, combine this function with
/// `hash_upper_leaf()` function.
pub fn hash_bottom_leaf(values: &[(RpoDigest, Word)]) -> RpoDigest {
    let mut elements = Vec::with_capacity(values.len() * 8);
    for (key, val) in values.iter() {
        elements.extend_from_slice(key.as_elements());
        elements.extend_from_slice(val.as_slice());
    }
    // TODO: hash in domain
    Rpo256::hash_elements(&elements)
}
