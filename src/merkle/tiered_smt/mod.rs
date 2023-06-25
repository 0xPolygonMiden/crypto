use super::{
    BTreeMap, BTreeSet, EmptySubtreeRoots, Felt, InnerNodeInfo, MerkleError, MerklePath, NodeIndex,
    Rpo256, RpoDigest, StarkField, Vec, Word, ZERO,
};
use core::cmp;

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
/// For example, when the first key-value is inserted, it will be stored in a node at depth 16
/// such that the first 16 bits of the key determine the position of the node at depth 16. If
/// another value with a key sharing the same 16-bit prefix is inserted, both values move into
/// the next tier (depth 32). This process is repeated until values end up at tier 64. If multiple
/// values have keys with a common 64-bit prefix, such key-value pairs are stored in a sorted list
/// at the last tier (depth = 64).
///
/// To differentiate between internal and leaf nodes, node values are computed as follows:
/// - Internal nodes: hash(left_child, right_child).
/// - Leaf node at depths 16, 32, or 64: hash(rem_key, value, domain=depth).
/// - Leaf node at depth 64: hash([rem_key_0, value_0, ..., rem_key_n, value_n, domain=64]).
///
/// Where rem_key is computed by replacing d most significant bits of the key with zeros where d
/// is depth (i.e., for a leaf at depth 16, we replace 16 most significant bits of the key with 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TieredSmt {
    root: RpoDigest,
    nodes: BTreeMap<NodeIndex, RpoDigest>,
    upper_leaves: BTreeMap<NodeIndex, RpoDigest>, // node_index |-> key map
    bottom_leaves: BTreeMap<u64, BottomLeaf>,     // leaves of depth 64
    values: BTreeMap<RpoDigest, Word>,
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
        self.validate_node_access(index)?;
        Ok(self.get_node_unchecked(&index))
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
    pub fn get_path(&self, mut index: NodeIndex) -> Result<MerklePath, MerkleError> {
        self.validate_node_access(index)?;

        let mut path = Vec::with_capacity(index.depth() as usize);
        for _ in 0..index.depth() {
            let node = self.get_node_unchecked(&index.sibling());
            path.push(node);
            index.move_up();
        }

        Ok(path.into())
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
        // insert the value into the key-value map, and if nothing has changed, return
        let old_value = self.values.insert(key, value).unwrap_or(Self::EMPTY_VALUE);
        if old_value == value {
            return old_value;
        }

        // determine the index for the value node; this index could have 3 different meanings:
        // - it points to a root of an empty subtree (excluding depth = 64); in this case, we can
        //   replace the node with the value node immediately.
        // - it points to a node at the bottom tier (i.e., depth = 64); in this case, we need to
        //   process bottom-tier insertion which will be handled by insert_node().
        // - it points to a leaf node; this node could be a node with the same key or a different
        //   key with a common prefix; in the latter case, we'll need to move the leaf to a lower
        //   tier; for this scenario the `leaf_key` will contain the key of the leaf node
        let (mut index, leaf_key) = self.get_insert_location(&key);

        // if the returned index points to a leaf, and this leaf is for a different key, we need
        // to move the leaf to a lower tier
        if let Some(other_key) = leaf_key {
            if other_key != key {
                // determine how far down the tree should we move the existing leaf
                let common_prefix_len = get_common_prefix_tier(&key, &other_key);
                let depth = cmp::min(common_prefix_len + Self::TIER_SIZE, Self::MAX_DEPTH);

                // move the leaf to the new location; this requires first removing the existing
                // index, re-computing node value, and inserting the node at a new location
                let other_index = key_to_index(&other_key, depth);
                let other_value = *self.values.get(&other_key).expect("no value for other key");
                self.upper_leaves.remove(&index).expect("other node key not in map");
                self.insert_node(other_index, other_key, other_value);

                // the new leaf also needs to move down to the same tier
                index = key_to_index(&key, depth);
            }
        }

        // insert the node and return the old value
        self.insert_node(index, key, value);
        old_value
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over all inner nodes of this [TieredSmt] (i.e., nodes not at depths 16
    /// 32, 48, or 64).
    ///
    /// The iterator order is unspecified.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.nodes.iter().filter_map(|(index, node)| {
            if is_inner_node(index) {
                Some(InnerNodeInfo {
                    value: *node,
                    left: self.get_node_unchecked(&index.left_child()),
                    right: self.get_node_unchecked(&index.right_child()),
                })
            } else {
                None
            }
        })
    }

    /// Returns an iterator over upper leaves (i.e., depth = 16, 32, or 48) for this [TieredSmt].
    ///
    /// Each yielded item is a (node, key, value) tuple where key is a full un-truncated key (i.e.,
    /// with key[3] element unmodified).
    ///
    /// The iterator order is unspecified.
    pub fn upper_leaves(&self) -> impl Iterator<Item = (RpoDigest, RpoDigest, Word)> + '_ {
        self.upper_leaves.iter().map(|(index, key)| {
            let node = self.get_node_unchecked(index);
            let value = self.get_value(*key);
            (node, *key, value)
        })
    }

    /// Returns an iterator over bottom leaves (i.e., depth = 64) of this [TieredSmt].
    ///
    /// Each yielded item consists of the hash of the leaf and its contents, where contents is
    /// a vector containing key-value pairs of entries storied in this leaf. Note that keys are
    /// un-truncated keys (i.e., with key[3] element unmodified).
    ///
    /// The iterator order is unspecified.
    pub fn bottom_leaves(&self) -> impl Iterator<Item = (RpoDigest, Vec<(RpoDigest, Word)>)> + '_ {
        self.bottom_leaves.values().map(|leaf| (leaf.hash(), leaf.contents()))
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Checks if the specified index is valid in the context of this Merkle tree.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The specified index depth is 0 or greater than 64.
    /// - The node for the specified index does not exists in the Merkle tree. This is possible
    ///   when an ancestors of the specified index is a leaf node.
    fn validate_node_access(&self, index: NodeIndex) -> Result<(), MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > Self::MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        } else {
            // make sure that there are no leaf nodes in the ancestors of the index; since leaf
            // nodes can live at specific depth, we just need to check these depths.
            let tier = get_index_tier(&index);
            let mut tier_index = index;
            for &depth in Self::TIER_DEPTHS[..tier].iter().rev() {
                tier_index.move_up_to(depth);
                if self.upper_leaves.contains_key(&tier_index) {
                    return Err(MerkleError::NodeNotInSet(index));
                }
            }
        }

        Ok(())
    }

    /// Returns a node at the specified index. If the node does not exist at this index, a root
    /// for an empty subtree at the index's depth is returned.
    ///
    /// Unlike [TieredSmt::get_node()] this does not perform any checks to verify that the returned
    /// node is valid in the context of this tree.
    fn get_node_unchecked(&self, index: &NodeIndex) -> RpoDigest {
        match self.nodes.get(index) {
            Some(node) => *node,
            None => EmptySubtreeRoots::empty_hashes(Self::MAX_DEPTH)[index.depth() as usize],
        }
    }

    /// Returns an index at which a node for the specified key should be inserted. If a leaf node
    /// already exists at that index, returns the key associated with that leaf node.
    ///
    /// In case the index falls into the bottom tier (depth = 64), leaf node key is not returned
    /// as the bottom tier may contain multiple key-value pairs in the same leaf.
    fn get_insert_location(&self, key: &RpoDigest) -> (NodeIndex, Option<RpoDigest>) {
        // traverse the tree from the root down checking nodes at tiers 16, 32, and 48. Return if
        // a node at any of the tiers is either a leaf or a root of an empty subtree.
        let mse = Word::from(key)[3].as_int();
        for depth in (Self::TIER_DEPTHS[0]..Self::MAX_DEPTH).step_by(Self::TIER_SIZE as usize) {
            let index = NodeIndex::new_unchecked(depth, mse >> (Self::MAX_DEPTH - depth));
            if let Some(leaf_key) = self.upper_leaves.get(&index) {
                return (index, Some(*leaf_key));
            } else if !self.nodes.contains_key(&index) {
                return (index, None);
            }
        }

        // if we got here, that means all of the nodes checked so far are internal nodes, and
        // the new node would need to be inserted in the bottom tier.
        let index = NodeIndex::new_unchecked(Self::MAX_DEPTH, mse);
        (index, None)
    }

    /// Inserts the provided key-value pair at the specified index and updates the root of this
    /// Merkle tree by recomputing the path to the root.
    fn insert_node(&mut self, mut index: NodeIndex, key: RpoDigest, value: Word) {
        let depth = index.depth();

        // insert the key into index-key map and compute the new value of the node
        let mut node = if index.depth() == Self::MAX_DEPTH {
            // for the bottom tier, we add the key-value pair to the existing leaf, or create a
            // new leaf with this key-value pair
            self.bottom_leaves
                .entry(index.value())
                .and_modify(|leaves| leaves.add_value(key, value))
                .or_insert(BottomLeaf::new(key, value))
                .hash()
        } else {
            // for the upper tiers, we just update the index-key map and compute the value of the
            // node
            self.upper_leaves.insert(index, key);
            // the node value is computed as: hash(remaining_key || value, domain = depth)
            let remaining_path = get_remaining_path(key, depth.into());
            Rpo256::merge_in_domain(&[remaining_path, value.into()], depth.into())
        };

        // insert the node and update the path from the node to the root
        for _ in 0..index.depth() {
            self.nodes.insert(index, node);
            let sibling = self.get_node_unchecked(&index.sibling());
            node = Rpo256::merge(&index.build_node(node, sibling));
            index.move_up();
        }

        // update the root
        self.nodes.insert(NodeIndex::root(), node);
        self.root = node;
    }
}

impl Default for TieredSmt {
    fn default() -> Self {
        Self {
            root: EmptySubtreeRoots::empty_hashes(Self::MAX_DEPTH)[0],
            nodes: BTreeMap::new(),
            upper_leaves: BTreeMap::new(),
            bottom_leaves: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the remaining path for the specified key at the specified depth.
///
/// Remaining path is computed by setting n most significant bits of the key to zeros, where n is
/// the specified depth.
fn get_remaining_path(key: RpoDigest, depth: u32) -> RpoDigest {
    let mut key = Word::from(key);
    key[3] = if depth == 64 {
        ZERO
    } else {
        // remove `depth` bits from the most significant key element
        ((key[3].as_int() << depth) >> depth).into()
    };
    key.into()
}

/// Returns index for the specified key inserted at the specified depth.
///
/// The value for the key is computed by taking n most significant bits from the most significant
/// element of the key, where n is the specified depth.
fn key_to_index(key: &RpoDigest, depth: u8) -> NodeIndex {
    let mse = Word::from(key)[3].as_int();
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
    let e1 = Word::from(key1)[3].as_int();
    let e2 = Word::from(key2)[3].as_int();
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

/// Returns true if the specified index is an index for an inner node (i.e., the depth is not 16,
/// 32, 48, or 64).
const fn is_inner_node(index: &NodeIndex) -> bool {
    !matches!(index.depth(), 16 | 32 | 48 | 64)
}

// BOTTOM LEAF
// ================================================================================================

/// Stores contents of the bottom leaf (i.e., leaf at depth = 64) in a [TieredSmt].
///
/// Bottom leaf can contain one or more key-value pairs all sharing the same 64-bit key prefix.
/// The values are sorted by key to make sure the structure of the leaf is independent of the
/// insertion order. This guarantees that a leaf with the same set of key-value pairs always has
/// the same hash value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BottomLeaf {
    prefix: u64,
    values: BTreeMap<[u64; 4], Word>,
}

impl BottomLeaf {
    /// Returns a new [BottomLeaf] with a single key-value pair added.
    pub fn new(key: RpoDigest, value: Word) -> Self {
        let prefix = Word::from(key)[3].as_int();
        let mut values = BTreeMap::new();
        let key = get_remaining_path(key, TieredSmt::MAX_DEPTH as u32);
        values.insert(key.into(), value);
        Self { prefix, values }
    }

    /// Adds a new key-value pair to this leaf.
    pub fn add_value(&mut self, key: RpoDigest, value: Word) {
        let key = get_remaining_path(key, TieredSmt::MAX_DEPTH as u32);
        self.values.insert(key.into(), value);
    }

    /// Computes a hash of this leaf.
    pub fn hash(&self) -> RpoDigest {
        let mut elements = Vec::with_capacity(self.values.len() * 2);
        for (key, val) in self.values.iter() {
            key.iter().for_each(|&v| elements.push(Felt::new(v)));
            elements.extend_from_slice(val.as_slice());
        }
        // TODO: hash in domain
        Rpo256::hash_elements(&elements)
    }

    /// Returns contents of this leaf as a vector of (key, value) pairs.
    ///
    /// The keys are returned in their un-truncated form.
    pub fn contents(&self) -> Vec<(RpoDigest, Word)> {
        self.values
            .iter()
            .map(|(key, val)| {
                let key = RpoDigest::from([
                    Felt::new(key[0]),
                    Felt::new(key[1]),
                    Felt::new(key[2]),
                    Felt::new(self.prefix),
                ]);
                (key, *val)
            })
            .collect()
    }
}
