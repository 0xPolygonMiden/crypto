use super::{
    get_index_tier, get_key_prefix, is_leaf_node, BTreeMap, BTreeSet, EmptySubtreeRoots,
    InnerNodeInfo, MerkleError, MerklePath, NodeIndex, Rpo256, RpoDigest, Vec,
};

// CONSTANTS
// ================================================================================================

/// The number of levels between tiers.
const TIER_SIZE: u8 = super::TieredSmt::TIER_SIZE;

/// Depths at which leaves can exist in a tiered SMT.
const TIER_DEPTHS: [u8; 4] = super::TieredSmt::TIER_DEPTHS;

/// Maximum node depth. This is also the bottom tier of the tree.
const MAX_DEPTH: u8 = super::TieredSmt::MAX_DEPTH;

// NODE STORE
// ================================================================================================

/// A store of nodes for a Tiered Sparse Merkle tree.
///
/// The store contains information about all nodes as well as information about which of the nodes
/// represent leaf nodes in a Tiered Sparse Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStore {
    nodes: BTreeMap<NodeIndex, RpoDigest>,
    upper_leaves: BTreeSet<NodeIndex>,
    bottom_leaves: BTreeSet<u64>,
}

impl NodeStore {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [NodeStore] instantiated with the specified root node.
    ///
    /// Root node is assumed to be a root of an empty sparse Merkle tree.
    pub fn new(root_node: RpoDigest) -> Self {
        let mut nodes = BTreeMap::default();
        nodes.insert(NodeIndex::root(), root_node);

        Self {
            nodes,
            upper_leaves: BTreeSet::default(),
            bottom_leaves: BTreeSet::default(),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

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

    /// Returns an index at which a leaf node for the specified key should be inserted.
    ///
    /// The second value in the returned tuple is set to true if the node at the returned index
    /// is already a leaf node, excluding leaves at the bottom tier (i.e., if the leaf is at the
    /// bottom tier, false is returned).
    pub fn get_insert_location(&self, key: &RpoDigest) -> (NodeIndex, bool) {
        // traverse the tree from the root down checking nodes at tiers 16, 32, and 48. Return if
        // a node at any of the tiers is either a leaf or a root of an empty subtree.
        let mse = get_key_prefix(key);
        for depth in (TIER_DEPTHS[0]..MAX_DEPTH).step_by(TIER_SIZE as usize) {
            let index = NodeIndex::new_unchecked(depth, mse >> (MAX_DEPTH - depth));
            if self.upper_leaves.contains(&index) {
                return (index, true);
            } else if !self.nodes.contains_key(&index) {
                return (index, false);
            }
        }

        // if we got here, that means all of the nodes checked so far are internal nodes, and
        // the new node would need to be inserted in the bottom tier.
        let index = NodeIndex::new_unchecked(MAX_DEPTH, mse);
        (index, false)
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over all inner nodes of the Tiered Sparse Merkle tree (i.e., nodes not
    /// at depths 16 32, 48, or 64).
    ///
    /// The iterator order is unspecified.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.nodes.iter().filter_map(|(index, node)| {
            if !is_leaf_node(index) {
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

    /// Returns an iterator over the upper leaves (i.e., leaves with depths 16, 32, 48) of the
    /// Tiered Sparse Merkle tree.
    pub fn upper_leaves(&self) -> impl Iterator<Item = (&NodeIndex, &RpoDigest)> {
        self.upper_leaves.iter().map(|index| (index, &self.nodes[index]))
    }

    /// Returns an iterator over the bottom leaves (i.e., leaves with depth 64) of the Tiered
    /// Sparse Merkle tree.
    pub fn bottom_leaves(&self) -> impl Iterator<Item = (&u64, &RpoDigest)> {
        self.bottom_leaves.iter().map(|value| {
            let index = NodeIndex::new_unchecked(MAX_DEPTH, *value);
            (value, &self.nodes[&index])
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Replaces the leaf node at the specified index with a tree consisting of two leaves located
    /// at the specified indexes. Recomputes and returns the new root.
    pub fn replace_leaf_with_subtree(
        &mut self,
        leaf_index: NodeIndex,
        subtree_leaves: [(NodeIndex, RpoDigest); 2],
    ) -> RpoDigest {
        debug_assert!(is_leaf_node(&leaf_index));
        debug_assert!(is_leaf_node(&subtree_leaves[0].0));
        debug_assert!(is_leaf_node(&subtree_leaves[1].0));
        debug_assert!(!is_empty_root(&subtree_leaves[0].1));
        debug_assert!(!is_empty_root(&subtree_leaves[1].1));
        debug_assert_eq!(subtree_leaves[0].0.depth(), subtree_leaves[1].0.depth());
        debug_assert!(leaf_index.depth() < subtree_leaves[0].0.depth());

        self.upper_leaves.remove(&leaf_index);
        self.insert_leaf_node(subtree_leaves[0].0, subtree_leaves[0].1);
        self.insert_leaf_node(subtree_leaves[1].0, subtree_leaves[1].1)
    }

    /// Replaces a subtree containing the retained and the removed leaf nodes, with a leaf node
    /// containing the retained leaf.
    ///
    /// This has the effect of deleting the the node at the `removed_leaf` index from the tree,
    /// moving the node at the `retained_leaf` index up to the tier specified by `new_depth`.
    pub fn replace_subtree_with_leaf(
        &mut self,
        removed_leaf: NodeIndex,
        retained_leaf: NodeIndex,
        new_depth: u8,
        node: RpoDigest,
    ) -> RpoDigest {
        debug_assert!(!is_empty_root(&node));
        debug_assert!(self.is_leaf(&removed_leaf));
        debug_assert!(self.is_leaf(&retained_leaf));
        debug_assert_eq!(removed_leaf.depth(), retained_leaf.depth());
        debug_assert!(removed_leaf.depth() > new_depth);

        // clear leaf flags
        if removed_leaf.depth() == MAX_DEPTH {
            self.bottom_leaves.remove(&removed_leaf.value());
            self.bottom_leaves.remove(&retained_leaf.value());
        } else {
            self.upper_leaves.remove(&removed_leaf);
            self.upper_leaves.remove(&retained_leaf);
        }

        // remove the branches leading up to the tier to which the retained leaf is to be moved
        self.remove_branch(removed_leaf, new_depth);
        self.remove_branch(retained_leaf, new_depth);

        // compute the index of the common root for retained and removed leaves
        let mut new_index = retained_leaf;
        new_index.move_up_to(new_depth);
        debug_assert!(is_leaf_node(&new_index));

        // insert the node at the root index
        self.insert_leaf_node(new_index, node)
    }

    /// Inserts the specified node at the specified index; recomputes and returns the new root
    /// of the Tiered Sparse Merkle tree.
    ///
    /// This method assumes that node is a non-empty value.
    pub fn insert_leaf_node(&mut self, mut index: NodeIndex, mut node: RpoDigest) -> RpoDigest {
        debug_assert!(is_leaf_node(&index));
        debug_assert!(!is_empty_root(&node));

        // mark the node as the leaf
        if index.depth() == MAX_DEPTH {
            self.bottom_leaves.insert(index.value());
        } else {
            self.upper_leaves.insert(index);
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
        node
    }

    /// Updates the node at the specified index with the specified node value; recomputes and
    /// returns the new root of the Tiered Sparse Merkle tree.
    ///
    /// This method can accept `node` as either an empty or a non-empty value.
    pub fn update_leaf_node(&mut self, mut index: NodeIndex, mut node: RpoDigest) -> RpoDigest {
        debug_assert!(self.is_leaf(&index));

        // if the value we are updating the node to is a root of an empty tree, clear the leaf
        // flag for this node
        if node == EmptySubtreeRoots::empty_hashes(MAX_DEPTH)[index.depth() as usize] {
            if index.depth() == MAX_DEPTH {
                self.bottom_leaves.remove(&index.value());
            } else {
                self.upper_leaves.remove(&index);
            }
        } else {
            debug_assert!(!is_empty_root(&node));
        }

        // update the path from the node to the root
        for _ in 0..index.depth() {
            if node == EmptySubtreeRoots::empty_hashes(MAX_DEPTH)[index.depth() as usize] {
                self.nodes.remove(&index);
            } else {
                self.nodes.insert(index, node);
            }

            let sibling = self.get_node_unchecked(&index.sibling());
            node = Rpo256::merge(&index.build_node(node, sibling));
            index.move_up();
        }

        // update the root
        self.nodes.insert(NodeIndex::root(), node);
        node
    }

    /// Replaces the leaf node at the specified index with a root of an empty subtree; recomputes
    /// and returns the new root of the Tiered Sparse Merkle tree.
    pub fn clear_leaf_node(&mut self, index: NodeIndex) -> RpoDigest {
        debug_assert!(self.is_leaf(&index));
        let node = EmptySubtreeRoots::empty_hashes(MAX_DEPTH)[index.depth() as usize];
        self.update_leaf_node(index, node)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns true if the node at the specified index is a leaf node.
    fn is_leaf(&self, index: &NodeIndex) -> bool {
        debug_assert!(is_leaf_node(index));
        if index.depth() == MAX_DEPTH {
            self.bottom_leaves.contains(&index.value())
        } else {
            self.upper_leaves.contains(index)
        }
    }

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
        } else if index.depth() > MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        } else {
            // make sure that there are no leaf nodes in the ancestors of the index; since leaf
            // nodes can live at specific depth, we just need to check these depths.
            let tier = get_index_tier(&index);
            let mut tier_index = index;
            for &depth in TIER_DEPTHS[..tier].iter().rev() {
                tier_index.move_up_to(depth);
                if self.upper_leaves.contains(&tier_index) {
                    return Err(MerkleError::NodeNotInSet(index));
                }
            }
        }

        Ok(())
    }

    /// Returns a node at the specified index. If the node does not exist at this index, a root
    /// for an empty subtree at the index's depth is returned.
    ///
    /// Unlike [NodeStore::get_node()] this does not perform any checks to verify that the
    /// returned node is valid in the context of this tree.
    fn get_node_unchecked(&self, index: &NodeIndex) -> RpoDigest {
        match self.nodes.get(index) {
            Some(node) => *node,
            None => EmptySubtreeRoots::empty_hashes(MAX_DEPTH)[index.depth() as usize],
        }
    }

    /// Removes a sequence of nodes starting at the specified index and traversing the
    /// tree up to the specified depth.
    ///
    /// This method does not update any other nodes and does not recompute the tree root.
    fn remove_branch(&mut self, mut index: NodeIndex, end_depth: u8) {
        assert!(index.depth() > end_depth);
        for _ in 0..(index.depth() - end_depth) {
            self.nodes.remove(&index);
            index.move_up()
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns true if the specified node is a root of an empty tree or an empty value ([ZERO; 4]).
fn is_empty_root(node: &RpoDigest) -> bool {
    EmptySubtreeRoots::empty_hashes(MAX_DEPTH).contains(node)
}
