use super::{
    BTreeMap, BTreeSet, EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, NodeIndex,
    Rpo256, RpoDigest, StarkField, Vec, Word,
};
use core::cmp;

mod nodes;
use nodes::NodeStore;

mod values;
use values::ValueStore;

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
/// - Leaf node at depth 64: hash([key_0, value_0, ..., key_n, value_n, domain=64]).
#[derive(Debug, Clone, PartialEq, Eq)]
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

        // insert the value into the value store, and if nothing has changed, return
        let (old_value, is_update) = match self.values.insert(key, value) {
            Some(old_value) => {
                if old_value == value {
                    return old_value;
                }
                (old_value, true)
            }
            None => (Self::EMPTY_VALUE, false),
        };

        // determine the index for the value node; this index could have 3 different meanings:
        // - it points to a root of an empty subtree (excluding depth = 64); in this case, we can
        //   replace the node with the value node immediately.
        // - it points to a node at the bottom tier (i.e., depth = 64); in this case, we need to
        //   process bottom-tier insertion which will be handled by insert_leaf_node().
        // - it points to an existing leaf node; this node could be a node with the same key or a
        //   different key with a common prefix; in the latter case, we'll need to move the leaf
        //   to a lower tier
        let (index, leaf_exists) = self.nodes.get_insert_location(&key);
        debug_assert!(!is_update || leaf_exists);

        // if the returned index points to a leaf, and this leaf is for a different key (i.e., we
        // are not updating a value for an existing key), we need to replace this leaf with a tree
        // containing leaves for both the old and the new key-value pairs
        if leaf_exists && !is_update {
            // get the key-value pair for the key with the same prefix; since the key-value
            // pair has already been inserted into the value store, we need to filter it out
            // when looking for the other key-value pair
            let (other_key, other_value) = self
                .values
                .get_first_filtered(index_to_prefix(&index), &key)
                .expect("other key-value pair not found");

            // determine how far down the tree should we move the leaves
            let common_prefix_len = get_common_prefix_tier(&key, other_key);
            let depth = cmp::min(common_prefix_len + Self::TIER_SIZE, Self::MAX_DEPTH);

            // compute node locations for new and existing key-value paris
            let new_index = key_to_index(&key, depth);
            let other_index = key_to_index(other_key, depth);

            // compute node values for the new and existing key-value pairs
            let new_node = self.build_leaf_node(new_index, key, value);
            let other_node = self.build_leaf_node(other_index, *other_key, *other_value);

            // replace the leaf located at index with a subtree containing nodes for new and
            // existing key-value paris
            self.root = self.nodes.replace_leaf_with_subtree(
                index,
                [(new_index, new_node), (other_index, other_node)],
            );
        } else {
            // if the returned index points to an empty subtree, or a leaf with the same key (i.e.,
            // we are performing an update), or a leaf is at the bottom tier, compute its node
            // value and do a simple insert
            let node = self.build_leaf_node(index, key, value);
            self.root = self.nodes.insert_leaf_node(index, node);
        }

        old_value
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

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
            (*node, *key, *value)
        })
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
        let (index, leaf_exists) = self.nodes.get_insert_location(&key);
        debug_assert!(index.depth() == Self::MAX_DEPTH || leaf_exists);

        // if the leaf is at the bottom tier and after removing the key-value pair from it, the
        // leaf is still not empty, just recompute its hash and update the leaf node.
        if index.depth() == Self::MAX_DEPTH {
            if let Some(values) = self.values.get_all(index.value()) {
                let node = hash_bottom_leaf(&values);
                self.root = self.nodes.update_leaf_node(index, node);
                return old_value;
            };
        }

        // if the removed key-value pair has a lone sibling at the current tier with a root at
        // higher tier, we need to move the sibling to a higher tier
        if let Some((sib_key, sib_val, new_sib_index)) = self.values.get_lone_sibling(index) {
            // determine the current index of the sibling node
            let sib_index = key_to_index(sib_key, index.depth());
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
    fn build_leaf_node(&self, index: NodeIndex, key: RpoDigest, value: Word) -> RpoDigest {
        let depth = index.depth();
        debug_assert!(Self::TIER_DEPTHS.contains(&depth));

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

/// Returns index for the specified key inserted at the specified depth.
///
/// The value for the key is computed by taking n most significant bits from the most significant
/// element of the key, where n is the specified depth.
fn key_to_index(key: &RpoDigest, depth: u8) -> NodeIndex {
    let mse = get_key_prefix(key);
    let value = match depth {
        16 | 32 | 48 | 64 => mse >> ((TieredSmt::MAX_DEPTH - depth) as u32),
        _ => unreachable!("invalid depth: {depth}"),
    };
    NodeIndex::new_unchecked(depth, value)
}

/// Returns tiered common prefix length between the most significant elements of the provided keys.
///
/// Specifically:
/// - returns 64 if the most significant elements are equal.
/// - returns 48 if the common prefix is between 48 and 63 bits.
/// - returns 32 if the common prefix is between 32 and 47 bits.
/// - returns 16 if the common prefix is between 16 and 31 bits.
/// - returns 0 if the common prefix is fewer than 16 bits.
fn get_common_prefix_tier(key1: &RpoDigest, key2: &RpoDigest) -> u8 {
    let e1 = get_key_prefix(key1);
    let e2 = get_key_prefix(key2);
    let ex = (e1 ^ e2).leading_zeros() as u8;
    (ex / 16) * 16
}

/// Returns a tier for the specified index.
///
/// The tiers are defined as follows:
/// - Tier 0: depth 0 through 16 (inclusive).
/// - Tier 1: depth 17 through 32 (inclusive).
/// - Tier 2: depth 33 through 48 (inclusive).
/// - Tier 3: depth 49 through 64 (inclusive).
const fn get_index_tier(index: &NodeIndex) -> usize {
    debug_assert!(index.depth() <= TieredSmt::MAX_DEPTH, "invalid depth");
    match index.depth() {
        0..=16 => 0,
        17..=32 => 1,
        33..=48 => 2,
        _ => 3,
    }
}

/// Returns true if the specified index is an index for an leaf node (i.e., the depth is 16, 32,
/// 48, or 64).
const fn is_leaf_node(index: &NodeIndex) -> bool {
    matches!(index.depth(), 16 | 32 | 48 | 64)
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
/// Node value is computed as: hash([key_0, value_0, ..., key_n, value_n, domain=64]).
pub fn hash_bottom_leaf(values: &[(RpoDigest, Word)]) -> RpoDigest {
    let mut elements = Vec::with_capacity(values.len() * 8);
    for (key, val) in values.iter() {
        elements.extend_from_slice(key.as_elements());
        elements.extend_from_slice(val.as_slice());
    }
    // TODO: hash in domain
    Rpo256::hash_elements(&elements)
}
