use super::{
    BTreeMap, BTreeSet, EmptySubtreeRoots, InnerNodeInfo, LeafNodeIndex, MerkleError, MerklePath,
    NodeIndex, Rpo256, RpoDigest, Vec,
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
/// represent leaf nodes in a Tiered Sparse Merkle tree. In the current implementation, [BTreeSet]s
/// are used to determine the position of the leaves in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
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

    /// Returns a Merkle path to the node specified by the key together with a flag indicating,
    /// whether this node is a leaf at depths 16, 32, or 48.
    pub fn get_proof(&self, key: &RpoDigest) -> (MerklePath, NodeIndex, bool) {
        let (index, leaf_exists) = self.get_leaf_index(key);
        let index: NodeIndex = index.into();
        let path = self.get_path(index).expect("failed to retrieve Merkle path for a node index");
        (path, index, leaf_exists)
    }

    /// Returns an index at which a leaf node for the specified key should be inserted.
    ///
    /// The second value in the returned tuple is set to true if the node at the returned index
    /// is already a leaf node.
    pub fn get_leaf_index(&self, key: &RpoDigest) -> (LeafNodeIndex, bool) {
        // traverse the tree from the root down checking nodes at tiers 16, 32, and 48. Return if
        // a node at any of the tiers is either a leaf or a root of an empty subtree.
        const NUM_UPPER_TIERS: usize = TIER_DEPTHS.len() - 1;
        for &tier_depth in TIER_DEPTHS[..NUM_UPPER_TIERS].iter() {
            let index = LeafNodeIndex::from_key(key, tier_depth);
            if self.upper_leaves.contains(&index) {
                return (index, true);
            } else if !self.nodes.contains_key(&index) {
                return (index, false);
            }
        }

        // if we got here, that means all of the nodes checked so far are internal nodes, and
        // the new node would need to be inserted in the bottom tier.
        let index = LeafNodeIndex::from_key(key, MAX_DEPTH);
        (index, self.bottom_leaves.contains(&index.value()))
    }

    /// Traverses the tree up from the bottom tier starting at the specified leaf index and
    /// returns the depth of the first node which hash more than one child. The returned depth
    /// is rounded up to the next tier.
    pub fn get_last_single_child_parent_depth(&self, leaf_index: u64) -> u8 {
        let mut index = NodeIndex::new_unchecked(MAX_DEPTH, leaf_index);

        for _ in (TIER_DEPTHS[0]..MAX_DEPTH).rev() {
            let sibling_index = index.sibling();
            if self.nodes.contains_key(&sibling_index) {
                break;
            }
            index.move_up();
        }

        let tier = (index.depth() - 1) / TIER_SIZE;
        TIER_DEPTHS[tier as usize]
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over all inner nodes of the Tiered Sparse Merkle tree (i.e., nodes not
    /// at depths 16 32, 48, or 64).
    ///
    /// The iterator order is unspecified.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.nodes.iter().filter_map(|(index, node)| {
            if self.is_internal_node(index) {
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
        leaf_index: LeafNodeIndex,
        subtree_leaves: [(LeafNodeIndex, RpoDigest); 2],
    ) -> RpoDigest {
        debug_assert!(self.is_non_empty_leaf(&leaf_index));
        debug_assert!(!is_empty_root(&subtree_leaves[0].1));
        debug_assert!(!is_empty_root(&subtree_leaves[1].1));
        debug_assert_eq!(subtree_leaves[0].0.depth(), subtree_leaves[1].0.depth());
        debug_assert!(leaf_index.depth() < subtree_leaves[0].0.depth());

        self.upper_leaves.remove(&leaf_index);

        if subtree_leaves[0].0 == subtree_leaves[1].0 {
            // if the subtree is for a single node at depth 64, we only need to insert one node
            debug_assert_eq!(subtree_leaves[0].0.depth(), MAX_DEPTH);
            debug_assert_eq!(subtree_leaves[0].1, subtree_leaves[1].1);
            self.insert_leaf_node(subtree_leaves[0].0, subtree_leaves[0].1)
        } else {
            self.insert_leaf_node(subtree_leaves[0].0, subtree_leaves[0].1);
            self.insert_leaf_node(subtree_leaves[1].0, subtree_leaves[1].1)
        }
    }

    /// Replaces a subtree containing the retained and the removed leaf nodes, with a leaf node
    /// containing the retained leaf.
    ///
    /// This has the effect of deleting the the node at the `removed_leaf` index from the tree,
    /// moving the node at the `retained_leaf` index up to the tier specified by `new_depth`.
    pub fn replace_subtree_with_leaf(
        &mut self,
        removed_leaf: LeafNodeIndex,
        retained_leaf: LeafNodeIndex,
        new_depth: u8,
        node: RpoDigest,
    ) -> RpoDigest {
        debug_assert!(!is_empty_root(&node));
        debug_assert!(self.is_non_empty_leaf(&removed_leaf));
        debug_assert!(self.is_non_empty_leaf(&retained_leaf));
        debug_assert_eq!(removed_leaf.depth(), retained_leaf.depth());
        debug_assert!(removed_leaf.depth() > new_depth);

        // remove the branches leading up to the tier to which the retained leaf is to be moved
        self.remove_branch(removed_leaf, new_depth);
        self.remove_branch(retained_leaf, new_depth);

        // compute the index of the common root for retained and removed leaves
        let mut new_index = retained_leaf;
        new_index.move_up_to(new_depth);

        // insert the node at the root index
        self.insert_leaf_node(new_index, node)
    }

    /// Inserts the specified node at the specified index; recomputes and returns the new root
    /// of the Tiered Sparse Merkle tree.
    ///
    /// This method assumes that the provided node is a non-empty value, and that there is no node
    /// at the specified index.
    pub fn insert_leaf_node(&mut self, index: LeafNodeIndex, mut node: RpoDigest) -> RpoDigest {
        debug_assert!(!is_empty_root(&node));
        debug_assert_eq!(self.nodes.get(&index), None);

        // mark the node as the leaf
        if index.depth() == MAX_DEPTH {
            self.bottom_leaves.insert(index.value());
        } else {
            self.upper_leaves.insert(index.into());
        };

        // insert the node and update the path from the node to the root
        let mut index: NodeIndex = index.into();
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
    pub fn update_leaf_node(&mut self, index: LeafNodeIndex, mut node: RpoDigest) -> RpoDigest {
        debug_assert!(self.is_non_empty_leaf(&index));

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
        let mut index: NodeIndex = index.into();
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
    pub fn clear_leaf_node(&mut self, index: LeafNodeIndex) -> RpoDigest {
        debug_assert!(self.is_non_empty_leaf(&index));
        let node = EmptySubtreeRoots::empty_hashes(MAX_DEPTH)[index.depth() as usize];
        self.update_leaf_node(index, node)
    }

    /// Truncates a branch starting with specified leaf at the bottom tier to new depth.
    ///
    /// This involves removing the part of the branch below the new depth, and then inserting a new
    /// // node at the new depth.
    pub fn truncate_branch(
        &mut self,
        leaf_index: u64,
        new_depth: u8,
        node: RpoDigest,
    ) -> RpoDigest {
        debug_assert!(self.bottom_leaves.contains(&leaf_index));

        let mut leaf_index = LeafNodeIndex::new(NodeIndex::new_unchecked(MAX_DEPTH, leaf_index));
        self.remove_branch(leaf_index, new_depth);

        leaf_index.move_up_to(new_depth);
        self.insert_leaf_node(leaf_index, node)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns true if the node at the specified index is a leaf node.
    fn is_non_empty_leaf(&self, index: &LeafNodeIndex) -> bool {
        if index.depth() == MAX_DEPTH {
            self.bottom_leaves.contains(&index.value())
        } else {
            self.upper_leaves.contains(index)
        }
    }

    /// Returns true if the node at the specified index is an internal node - i.e., there is
    /// no leaf at that node and the node does not belong to the bottom tier.
    fn is_internal_node(&self, index: &NodeIndex) -> bool {
        if index.depth() == MAX_DEPTH {
            false
        } else {
            !self.upper_leaves.contains(index)
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
            let tier = ((index.depth() - 1) / TIER_SIZE) as usize;
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

    /// Removes a sequence of nodes starting at the specified index and traversing the tree up to
    /// the specified depth. The node at the `end_depth` is also removed, and the appropriate leaf
    /// flag is cleared.
    ///
    /// This method does not update any other nodes and does not recompute the tree root.
    fn remove_branch(&mut self, index: LeafNodeIndex, end_depth: u8) {
        if index.depth() == MAX_DEPTH {
            self.bottom_leaves.remove(&index.value());
        } else {
            self.upper_leaves.remove(&index);
        }

        let mut index: NodeIndex = index.into();
        assert!(index.depth() > end_depth);
        for _ in 0..(index.depth() - end_depth + 1) {
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
