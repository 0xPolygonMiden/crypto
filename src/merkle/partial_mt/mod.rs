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
    root: RpoDigest,
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

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new emply [PartialMerkleTree].
    pub fn new() -> Self {
        PartialMerkleTree {
            root: Self::EMPTY_DIGEST,
            max_depth: 0,
            nodes: BTreeMap::new(),
            leaves: BTreeSet::new(),
        }
    }

    /// Returns a new [PartialMerkleTree] instantiated with leaves set as specified by the provided
    /// entries.
    ///
    /// # Errors
    /// Returns an error if:
    /// - If the depth is 0 or is greater than 64.
    /// - The number of entries exceeds the maximum tree capacity, that is 2^{depth}.
    /// - The provided entries contain multiple values for the same key.
    pub fn with_leaves<R, I>(entries: R) -> Result<Self, MerkleError>
    where
        R: IntoIterator<IntoIter = I>,
        I: Iterator<Item = (NodeIndex, RpoDigest)> + ExactSizeIterator,
    {
        // create an empty tree
        let mut tree = PartialMerkleTree::new();

        // check if the number of leaves can be accommodated by the tree's depth; we use a min
        // depth of 63 because we consider passing in a vector of size 2^64 infeasible.
        let entries = entries.into_iter();
        let max = (1_u64 << 63) as usize;
        if entries.len() > max {
            return Err(MerkleError::InvalidNumEntries(max, entries.len()));
        }

        for (node_index, rpo_digest) in entries {
            let old_value = tree.update_leaf(node_index, rpo_digest)?;
            if old_value != Self::EMPTY_DIGEST {
                return Err(MerkleError::DuplicateValuesForIndex(node_index.value()));
            }
        }
        Ok(tree)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of this Merkle tree.
    pub fn root(&self) -> Word {
        self.root.into()
    }

    /// Returns the depth of this Merkle tree.
    // TODO: maybe it's better to rename it to the `max_depth`
    pub fn depth(&self) -> u8 {
        self.max_depth
    }

    /// Returns a node at the specified NodeIndex.
    ///
    /// # Errors
    /// Returns an error if the specified NodeIndex is not contained in the nodes map.
    pub fn get_node(&self, index: NodeIndex) -> Result<Word, MerkleError> {
        self.nodes
            .get(&index)
            .ok_or(MerkleError::NodeNotInSet(index))
            .map(|hash| **hash)
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

    /// Returns a map of the all
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
        } else if index.depth() > self.depth() {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        }

        if !self.nodes.contains_key(&index) {
            return Err(MerkleError::NodeNotInSet(index));
        }

        let mut path = Vec::new();
        for _ in 0..index.depth() {
            let is_right = index.is_value_odd();
            let sibling_index = if is_right {
                NodeIndex::new(index.depth(), index.value() - 1)?
            } else {
                NodeIndex::new(index.depth(), index.value() + 1)?
            };
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
                (self.nodes.get(&left_index).cloned().unwrap_or(Self::EMPTY_DIGEST), value)
            } else {
                let right_index = NodeIndex::new(node_index.depth(), node_index.value() + 1)?;
                (value, self.nodes.get(&right_index).cloned().unwrap_or(Self::EMPTY_DIGEST))
            };
            node_index.move_up();
            value = Rpo256::merge(&[left, right]);
            self.nodes.insert(node_index, value);
        }

        self.root = value;
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
