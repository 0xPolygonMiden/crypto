use super::{
    BTreeMap, BTreeSet, MerkleError, MerklePath, NodeIndex, Rpo256, RpoDigest, ValuePath, Vec,
    Word, EMPTY_WORD,
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Index of the root node.
const ROOT_INDEX: NodeIndex = NodeIndex::root();

/// An RpoDigest consisting of 4 ZERO elements.
const EMPTY_DIGEST: RpoDigest = RpoDigest::new(EMPTY_WORD);

// PARTIAL MERKLE TREE
// ================================================================================================

/// A partial Merkle tree with NodeIndex keys and 4-element RpoDigest leaf values. Partial Merkle
/// Tree allows to create Merkle Tree by providing Merkle paths of different lengths.
///
/// The root of the tree is recomputed on each new leaf update.
pub struct PartialMerkleTree {
    max_depth: u8,
    nodes: BTreeMap<NodeIndex, RpoDigest>,
    leaves: BTreeSet<NodeIndex>,
}

impl Default for PartialMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialMerkleTree {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Minimum supported depth.
    pub const MIN_DEPTH: u8 = 1;

    /// Maximum supported depth.
    pub const MAX_DEPTH: u8 = 64;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new emply [PartialMerkleTree].
    pub fn new() -> Self {
        PartialMerkleTree {
            max_depth: 0,
            nodes: BTreeMap::new(),
            leaves: BTreeSet::new(),
        }
    }

    /// Appends the provided paths iterator into the set.
    ///
    /// Analogous to [Self::add_path].
    pub fn with_paths<I>(paths: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = (u64, RpoDigest, MerklePath)>,
    {
        // create an empty tree
        let tree = PartialMerkleTree::new();

        paths.into_iter().try_fold(tree, |mut tree, (index, value, path)| {
            tree.add_path(index, value, path)?;
            Ok(tree)
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of this Merkle tree.
    pub fn root(&self) -> RpoDigest {
        self.nodes.get(&ROOT_INDEX).cloned().unwrap_or(EMPTY_DIGEST)
    }

    /// Returns the depth of this Merkle tree.
    pub fn max_depth(&self) -> u8 {
        self.max_depth
    }

    /// Returns a node at the specified NodeIndex.
    ///
    /// # Errors
    /// Returns an error if the specified NodeIndex is not contained in the nodes map.
    pub fn get_node(&self, index: NodeIndex) -> Result<RpoDigest, MerkleError> {
        self.nodes.get(&index).ok_or(MerkleError::NodeNotInSet(index)).map(|hash| *hash)
    }

    /// Returns true if provided index contains in the leaves set, false otherwise.
    pub fn is_leaf(&self, index: NodeIndex) -> bool {
        self.leaves.contains(&index)
    }

    pub fn get_leaf_depth(&self, index: u64) -> Result<u8, MerkleError> {
        let mut node_index = NodeIndex::new(self.max_depth(), index)?;
        for _ in 0..node_index.depth() {
            if self.leaves.contains(&node_index) {
                return Ok(node_index.depth());
            }
            node_index.move_up()
        }
        Ok(0_u8)
    }

    /// Returns a vector of paths from every leaf to the root.
    pub fn paths(&self) -> Vec<(NodeIndex, ValuePath)> {
        let mut paths = Vec::new();
        self.leaves.iter().for_each(|leaf| {
            paths.push((
                *leaf,
                ValuePath {
                    value: *self.get_node(*leaf).expect("Failed to get leaf node"),
                    path: self.get_path(*leaf).expect("Failed to get path"),
                },
            ));
        });
        paths
    }

    /// Returns a Merkle path from the node at the specified index to the root.
    ///
    /// The node itself is not included in the path.
    ///
    /// # Errors
    /// Returns an error if:
    /// - the specified index has depth set to 0 or the depth is greater than the depth of this
    /// Merkle tree.
    /// - the specified index is not contained in the nodes map.
    pub fn get_path(&self, mut index: NodeIndex) -> Result<MerklePath, MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > self.max_depth() {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        }

        if !self.nodes.contains_key(&index) {
            return Err(MerkleError::NodeNotInSet(index));
        }

        let mut path = Vec::new();
        for _ in 0..index.depth() {
            let sibling_index = index.sibling();
            index.move_up();
            let sibling =
                self.nodes.get(&sibling_index).cloned().expect("Sibling node not in the map");
            path.push(Word::from(sibling));
        }
        Ok(MerklePath::new(path))
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [PartialMerkleTree].
    pub fn leaves(&self) -> impl Iterator<Item = (NodeIndex, RpoDigest)> + '_ {
        self.leaves.iter().map(|leaf| {
            (
                *leaf,
                self.get_node(*leaf).unwrap_or_else(|_| {
                    panic!(
                        "Leaf with node index ({}, {}) is not in the nodes map",
                        leaf.depth(),
                        leaf.value()
                    )
                }),
            )
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the nodes of the specified Merkle path to this [PartialMerkleTree]. The `index_value`
    /// and `value` parameters specify the leaf node at which the path starts.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The depth of the specified node_index is greater than 64 or smaller than 1.
    /// - The specified path is not consistent with other paths in the set (i.e., resolves to a
    ///   different root).
    pub fn add_path(
        &mut self,
        index_value: u64,
        value: RpoDigest,
        path: MerklePath,
    ) -> Result<(), MerkleError> {
        let index_value = NodeIndex::new(path.len() as u8, index_value)?;

        Self::check_depth(index_value.depth())?;
        self.update_depth(index_value.depth());

        // add provided node and its sibling to the leaves set
        self.leaves.insert(index_value);
        let sibling_node_index = index_value.sibling();
        self.leaves.insert(sibling_node_index);

        // add provided node and its sibling to the nodes map
        self.nodes.insert(index_value, value);
        self.nodes.insert(sibling_node_index, path[0].into());

        // traverse to the root, updating the nodes
        let mut index_value = index_value;
        let node = Rpo256::merge(&index_value.build_node(value, path[0].into()));
        let root = path.iter().skip(1).copied().fold(node, |node, hash| {
            index_value.move_up();
            // insert calculated node to the nodes map
            self.nodes.insert(index_value, node);

            // if the calculated node was a leaf, remove it from leaves set.
            if self.leaves.contains(&index_value) {
                self.leaves.remove(&index_value);
            }

            let sibling_node = index_value.sibling();
            // node became a leaf only if it is a new node (it wasn't in nodes map)
            if !self.nodes.contains_key(&sibling_node) {
                self.leaves.insert(sibling_node);
            }

            // insert node from Merkle path to the nodes map
            self.nodes.insert(sibling_node, hash.into());

            Rpo256::merge(&index_value.build_node(node, hash.into()))
        });

        // if the path set is empty (the root is all ZEROs), set the root to the root of the added
        // path; otherwise, the root of the added path must be identical to the current root
        if self.root() == EMPTY_DIGEST {
            self.nodes.insert(ROOT_INDEX, root);
        } else if self.root() != root {
            return Err(MerkleError::ConflictingRoots([*self.root(), *root].to_vec()));
        }

        // self.update_leaves()?;

        Ok(())
    }

    /// Updates value of the leaf at the specified index returning the old leaf value.
    ///
    /// This also recomputes all hashes between the leaf and the root, updating the root itself.
    pub fn update_leaf(
        &mut self,
        node_index: NodeIndex,
        value: RpoDigest,
    ) -> Result<RpoDigest, MerkleError> {
        // check correctness of the depth and update it
        Self::check_depth(node_index.depth())?;
        self.update_depth(node_index.depth());

        // insert NodeIndex to the leaves Set
        self.leaves.insert(node_index);

        // add node value to the nodes Map
        let old_value = self.nodes.insert(node_index, value).unwrap_or(EMPTY_DIGEST);

        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return Ok(value);
        }

        let mut node_index = node_index;
        let mut value = value;
        for _ in 0..node_index.depth() {
            let is_right = node_index.is_value_odd();
            let (left, right) = if is_right {
                let left_index = NodeIndex::new(node_index.depth(), node_index.value() - 1)?;
                (
                    self.nodes
                        .get(&left_index)
                        .cloned()
                        .ok_or(MerkleError::NodeNotInSet(left_index))?,
                    value,
                )
            } else {
                let right_index = NodeIndex::new(node_index.depth(), node_index.value() + 1)?;
                (
                    value,
                    self.nodes
                        .get(&right_index)
                        .cloned()
                        .ok_or(MerkleError::NodeNotInSet(right_index))?,
                )
            };
            node_index.move_up();
            value = Rpo256::merge(&[left, right]);
            self.nodes.insert(node_index, value);
        }

        Ok(old_value)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Updates depth value with the maximum of current and provided depth.
    fn update_depth(&mut self, new_depth: u8) {
        self.max_depth = new_depth.max(self.max_depth);
    }

    /// Returns an error if the depth is 0 or is greater than 64.
    fn check_depth(depth: u8) -> Result<(), MerkleError> {
        // validate the range of the depth.
        if depth < Self::MIN_DEPTH {
            return Err(MerkleError::DepthTooSmall(depth));
        } else if Self::MAX_DEPTH < depth {
            return Err(MerkleError::DepthTooBig(depth as u64));
        }
        Ok(())
    }
}
