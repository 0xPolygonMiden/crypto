use super::{
    BTreeMap, BTreeSet, InnerNodeInfo, MerkleError, MerklePath, NodeIndex, Rpo256, RpoDigest, Vec,
    Word, EMPTY_WORD,
};

#[cfg(test)]
mod tests;

// PARTIAL MERKLE TREE
// ================================================================================================

/// A partial Merkle tree with NodeIndex keys and 4-element RpoDigest leaf values.
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

    /// An RpoDigest consisting of 4 ZERO elements.
    pub const EMPTY_DIGEST: RpoDigest = RpoDigest::new(EMPTY_WORD);

    /// Minimum supported depth.
    pub const MIN_DEPTH: u8 = 1;

    /// Maximum supported depth.
    pub const MAX_DEPTH: u8 = 64;

    pub const ROOT_INDEX: NodeIndex = NodeIndex::new_unchecked(0, 0);

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
        I: IntoIterator<Item = (NodeIndex, Word, MerklePath)>,
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
    pub fn root(&self) -> Word {
        *self.nodes.get(&Self::ROOT_INDEX).cloned().unwrap_or(Self::EMPTY_DIGEST)
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
        // we don't have an error for this case, maybe it makes sense to create a new error, something like
        // NoLeafForIndex("There is no leaf for provided index"). But it will be used almost never.
        Err(MerkleError::NodeNotInSet(node_index))
    }

    /// Returns a value of the leaf at the specified NodeIndex.
    ///
    /// # Errors
    /// Returns an error if the NodeIndex is not contained in the leaves set.
    pub fn get_leaf(&self, index: NodeIndex) -> Result<Word, MerkleError> {
        if !self.leaves.contains(&index) {
            // This error not really suitable in this situation, should I create a new error?
            Err(MerkleError::InvalidIndex {
                depth: index.depth(),
                value: index.value(),
            })
        } else {
            self.nodes
                .get(&index)
                .ok_or(MerkleError::NodeNotInSet(index))
                .map(|hash| **hash)
        }
    }

    /// Returns a map of paths from every leaf to the root.
    pub fn paths(&self) -> Result<BTreeMap<&NodeIndex, MerklePath>, MerkleError> {
        let mut paths = BTreeMap::new();
        for leaf_index in self.leaves.iter() {
            let index = *leaf_index;
            paths.insert(leaf_index, self.get_path(index)?);
        }
        Ok(paths)
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
            let sibling_index = Self::get_sibling_index(&index)?;
            index.move_up();
            let sibling_hash =
                self.nodes.get(&sibling_index).cloned().unwrap_or(Self::EMPTY_DIGEST);
            path.push(Word::from(sibling_hash));
        }
        Ok(MerklePath::new(path))
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [PartialMerkleTree].
    pub fn leaves(&self) -> impl Iterator<Item = (NodeIndex, &Word)> {
        self.nodes
            .iter()
            .filter(|(index, _)| self.leaves.contains(index))
            .map(|(index, hash)| (*index, &(**hash)))
    }

    /// Returns an iterator over the inner nodes of this Merkle tree.
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        let inner_nodes = self.nodes.iter().filter(|(index, _)| !self.leaves.contains(index));
        inner_nodes.map(|(index, digest)| {
            let left_index = NodeIndex::new(index.depth() + 1, index.value() * 2)
                .expect("Failure to get left child index");
            let right_index = NodeIndex::new(index.depth() + 1, index.value() * 2 + 1)
                .expect("Failure to get right child index");
            let left_hash = self.nodes.get(&left_index).cloned().unwrap_or(Self::EMPTY_DIGEST);
            let right_hash = self.nodes.get(&right_index).cloned().unwrap_or(Self::EMPTY_DIGEST);
            InnerNodeInfo {
                value: **digest,
                left: *left_hash,
                right: *right_hash,
            }
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
        index_value: NodeIndex,
        value: Word,
        mut path: MerklePath,
    ) -> Result<(), MerkleError> {
        Self::check_depth(index_value.depth())?;
        self.update_depth(index_value.depth());

        // add node index to the leaves set
        self.leaves.insert(index_value);
        let sibling_node_index = Self::get_sibling_index(&index_value)?;
        self.leaves.insert(sibling_node_index);

        // add first two nodes to the nodes map
        self.nodes.insert(index_value, value.into());
        self.nodes.insert(sibling_node_index, path[0].into());

        // update the current path
        let parity = index_value.value() & 1;
        path.insert(parity as usize, value);

        // traverse to the root, updating the nodes
        let mut index_value = index_value;
        let root = Rpo256::merge(&[path[0].into(), path[1].into()]);
        let root = path.iter().skip(2).copied().fold(root, |root, hash| {
            index_value.move_up();
            // insert calculated node to the nodes map
            self.nodes.insert(index_value, root);

            let sibling_node = Self::get_sibling_index_unchecked(&index_value);
            // assume for now that all path nodes are leaves and add them to the leaves set
            self.leaves.insert(sibling_node);

            // insert node from Merkle path to the nodes map
            self.nodes.insert(sibling_node, hash.into());

            Rpo256::merge(&index_value.build_node(root, hash.into()))
        });

        let old_root = self.nodes.get(&Self::ROOT_INDEX).cloned().unwrap_or(Self::EMPTY_DIGEST);

        // if the path set is empty (the root is all ZEROs), set the root to the root of the added
        // path; otherwise, the root of the added path must be identical to the current root
        if old_root == Self::EMPTY_DIGEST {
            self.nodes.insert(Self::ROOT_INDEX, root);
        } else if old_root != root {
            return Err(MerkleError::ConflictingRoots([*old_root, *root].to_vec()));
        }

        self.update_leaves()?;

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
        let old_value = self.nodes.insert(node_index, value).unwrap_or(Self::EMPTY_DIGEST);

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

    fn get_sibling_index(node_index: &NodeIndex) -> Result<NodeIndex, MerkleError> {
        if node_index.is_value_odd() {
            NodeIndex::new(node_index.depth(), node_index.value() - 1)
        } else {
            NodeIndex::new(node_index.depth(), node_index.value() + 1)
        }
    }

    fn get_sibling_index_unchecked(node_index: &NodeIndex) -> NodeIndex {
        if node_index.is_value_odd() {
            NodeIndex::new_unchecked(node_index.depth(), node_index.value() - 1)
        } else {
            NodeIndex::new_unchecked(node_index.depth(), node_index.value() + 1)
        }
    }

    // Removes from the leaves set indexes of nodes which have descendants.
    fn update_leaves(&mut self) -> Result<(), MerkleError> {
        for leaf_node in self.leaves.clone().iter() {
            let left_child = NodeIndex::new(leaf_node.depth() + 1, leaf_node.value() * 2)?;
            let right_child = NodeIndex::new(leaf_node.depth() + 1, leaf_node.value() * 2 + 1)?;
            if self.nodes.contains_key(&left_child) || self.nodes.contains_key(&right_child) {
                self.leaves.remove(leaf_node);
            }
        }

        Ok(())
    }
}
