use super::{
    BTreeMap, BTreeSet, EmptySubtreeRoots, MerkleError, MerklePath, MerklePathSet, MerkleTree,
    NodeIndex, RootPath, Rpo256, RpoDigest, SimpleSmt, ValuePath, Vec, Word,
};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

#[cfg(test)]
mod tests;

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct Node {
    left: RpoDigest,
    right: RpoDigest,
}

/// An in-memory data store for Merkle-lized data.
///
/// This is a in memory data store for Merkle trees, this store allows all the nodes of multiple
/// trees to live as long as necessary and without duplication, this allows the implementation of
/// space efficient persistent data structures.
///
/// Example usage:
///
/// ```rust
/// # use miden_crypto::{ZERO, Felt, Word};
/// # use miden_crypto::merkle::{NodeIndex, MerkleStore, MerkleTree};
/// # use miden_crypto::hash::rpo::Rpo256;
/// # const fn int_to_node(value: u64) -> Word {
/// #     [Felt::new(value), ZERO, ZERO, ZERO]
/// # }
/// # let A = int_to_node(1);
/// # let B = int_to_node(2);
/// # let C = int_to_node(3);
/// # let D = int_to_node(4);
/// # let E = int_to_node(5);
/// # let F = int_to_node(6);
/// # let G = int_to_node(7);
/// # let H0 = int_to_node(8);
/// # let H1 = int_to_node(9);
/// # let T0 = MerkleTree::new([A, B, C, D, E, F, G, H0].to_vec()).expect("even number of leaves provided");
/// # let T1 = MerkleTree::new([A, B, C, D, E, F, G, H1].to_vec()).expect("even number of leaves provided");
/// # let ROOT0 = T0.root();
/// # let ROOT1 = T1.root();
/// let mut store = MerkleStore::new();
///
/// // the store is initialized with the SMT empty nodes
/// assert_eq!(store.num_internal_nodes(), 255);
///
/// // populates the store with two merkle trees, common nodes are shared
/// store.add_merkle_tree([A, B, C, D, E, F, G, H0]);
/// store.add_merkle_tree([A, B, C, D, E, F, G, H1]);
///
/// // every leaf except the last are the same
/// for i in 0..7 {
///     let d0 = store.get_node(ROOT0, NodeIndex::new(3, i)).unwrap();
///     let d1 = store.get_node(ROOT1, NodeIndex::new(3, i)).unwrap();
///     assert_eq!(d0, d1, "Both trees have the same leaf at pos {i}");
/// }
///
/// // The leafs A-B-C-D are the same for both trees, so are their 2 immediate parents
/// for i in 0..4 {
///     let d0 = store.get_path(ROOT0, NodeIndex::new(3, i)).unwrap();
///     let d1 = store.get_path(ROOT1, NodeIndex::new(3, i)).unwrap();
///     assert_eq!(d0.path[0..2], d1.path[0..2], "Both sub-trees are equal up to two levels");
/// }
///
/// // Common internal nodes are shared, the two added trees have a total of 30, but the store has
/// // only 10 new entries, corresponding to the 10 unique internal nodes of these trees.
/// assert_eq!(store.num_internal_nodes() - 255, 10);
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleStore {
    nodes: BTreeMap<RpoDigest, Node>,
}

impl Default for MerkleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleStore {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an empty `MerkleStore` instance.
    pub fn new() -> MerkleStore {
        // pre-populate the store with the empty hashes
        let subtrees = EmptySubtreeRoots::empty_hashes(255);
        let nodes = subtrees
            .iter()
            .rev()
            .copied()
            .zip(subtrees.iter().rev().skip(1).copied())
            .map(|(child, parent)| {
                (
                    parent,
                    Node {
                        left: child,
                        right: child,
                    },
                )
            })
            .collect();

        MerkleStore { nodes }
    }

    /// Appends the provided merkle tree represented by its `leaves` to the set.
    pub fn with_merkle_tree<I>(mut self, leaves: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = Word>,
    {
        self.add_merkle_tree(leaves)?;
        Ok(self)
    }

    /// Appends the provided sparse merkle tree represented by its `entries` to the set.
    pub fn with_sparse_merkle_tree<R, I>(mut self, entries: R) -> Result<Self, MerkleError>
    where
        R: IntoIterator<IntoIter = I>,
        I: Iterator<Item = (u64, Word)> + ExactSizeIterator,
    {
        self.add_sparse_merkle_tree(entries)?;
        Ok(self)
    }

    /// Appends the provided merkle path set.
    pub fn with_merkle_path(
        mut self,
        index_value: u64,
        node: Word,
        path: MerklePath,
    ) -> Result<Self, MerkleError> {
        self.add_merkle_path(index_value, node, path)?;
        Ok(self)
    }

    /// Appends the provided merkle path set.
    pub fn with_merkle_paths<I>(mut self, paths: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = (u64, Word, MerklePath)>,
    {
        self.add_merkle_paths(paths)?;
        Ok(self)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Return a count of the non-leaf nodes in the store.
    pub fn num_internal_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the node at `index` rooted on the tree `root`.
    ///
    /// # Errors
    ///
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the store.
    pub fn get_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleError> {
        let mut hash: RpoDigest = root.into();

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes
            .get(&hash)
            .ok_or(MerkleError::RootNotInStore(hash.into()))?;

        for bit in index.bit_iterator().rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeNotInStore(hash.into(), index))?;
            hash = if bit { node.right } else { node.left }
        }

        Ok(hash.into())
    }

    /// Returns the node at the specified `index` and its opening to the `root`.
    ///
    /// The path starts at the sibling of the target leaf.
    ///
    /// # Errors
    ///
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the store.
    pub fn get_path(&self, root: Word, index: NodeIndex) -> Result<ValuePath, MerkleError> {
        let mut hash: RpoDigest = root.into();
        let mut path = Vec::with_capacity(index.depth().into());

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes
            .get(&hash)
            .ok_or(MerkleError::RootNotInStore(hash.into()))?;

        for bit in index.bit_iterator().rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeNotInStore(hash.into(), index))?;

            hash = if bit {
                path.push(node.left.into());
                node.right
            } else {
                path.push(node.right.into());
                node.left
            }
        }

        // the path is computed from root to leaf, so it must be reversed
        path.reverse();

        Ok(ValuePath {
            value: hash.into(),
            path: MerklePath::new(path),
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds all the nodes of a Merkle tree represented by `leaves`.
    ///
    /// This will instantiate a Merkle tree using `leaves` and include all the nodes into the
    /// store.
    ///
    /// # Errors
    ///
    /// This method may return the following errors:
    /// - `DepthTooSmall` if leaves is empty or contains only 1 element
    /// - `NumLeavesNotPowerOfTwo` if the number of leaves is not a power-of-two
    pub fn add_merkle_tree<I>(&mut self, leaves: I) -> Result<Word, MerkleError>
    where
        I: IntoIterator<Item = Word>,
    {
        let leaves: Vec<_> = leaves.into_iter().collect();
        if leaves.len() < 2 {
            return Err(MerkleError::DepthTooSmall(leaves.len() as u8));
        }

        let layers = leaves.len().ilog2();
        let tree = MerkleTree::new(leaves)?;

        let mut depth = 0;
        let mut parent_offset = 1;
        let mut child_offset = 2;
        while depth < layers {
            let layer_size = 1usize << depth;
            for _ in 0..layer_size {
                // merkle tree is using level form representation, so left and right siblings are
                // next to each other
                let left = tree.nodes[child_offset];
                let right = tree.nodes[child_offset + 1];
                self.nodes.insert(
                    tree.nodes[parent_offset].into(),
                    Node {
                        left: left.into(),
                        right: right.into(),
                    },
                );
                parent_offset += 1;
                child_offset += 2;
            }
            depth += 1;
        }

        Ok(tree.nodes[1])
    }

    /// Adds all the nodes of a Sparse Merkle tree represented by `entries`.
    ///
    /// This will instantiate a Sparse Merkle tree using `entries` and include all the nodes into
    /// the store.
    ///
    /// # Errors
    ///
    /// This will return `InvalidEntriesCount` if the length of `entries` is not `63`.
    pub fn add_sparse_merkle_tree<R, I>(&mut self, entries: R) -> Result<Word, MerkleError>
    where
        R: IntoIterator<IntoIter = I>,
        I: Iterator<Item = (u64, Word)> + ExactSizeIterator,
    {
        let smt = SimpleSmt::new(SimpleSmt::MAX_DEPTH)?.with_leaves(entries)?;
        for branch in smt.store.branches.values() {
            let parent = Rpo256::merge(&[branch.left, branch.right]);
            self.nodes.insert(
                parent,
                Node {
                    left: branch.left,
                    right: branch.right,
                },
            );
        }

        Ok(smt.root())
    }

    /// Adds all the nodes of a Merkle path represented by `path`, opening to `node`. Returns the
    /// new root.
    ///
    /// This will compute the sibling elements determined by the Merkle `path` and `node`, and
    /// include all the nodes into the store.
    pub fn add_merkle_path(
        &mut self,
        index_value: u64,
        mut node: Word,
        path: MerklePath,
    ) -> Result<Word, MerkleError> {
        let mut index = NodeIndex::new(self.nodes.len() as u8, index_value);

        for sibling in path {
            let (left, right) = match index.is_value_odd() {
                true => (sibling, node),
                false => (node, sibling),
            };
            let parent = Rpo256::merge(&[left.into(), right.into()]);
            self.nodes.insert(
                parent,
                Node {
                    left: left.into(),
                    right: right.into(),
                },
            );

            index.move_up();
            node = parent.into();
        }

        Ok(node)
    }

    /// Adds all the nodes of multiple Merkle paths into the store.
    ///
    /// This will compute the sibling elements for each Merkle `path` and include all the nodes
    /// into the store.
    ///
    /// For further reference, check [MerkleStore::add_merkle_path].
    ///
    /// # Errors
    ///
    /// Every path must resolve to the same root, otherwise this will return an `ConflictingRoots`
    /// error.
    pub fn add_merkle_paths<I>(&mut self, paths: I) -> Result<Word, MerkleError>
    where
        I: IntoIterator<Item = (u64, Word, MerklePath)>,
    {
        let paths: Vec<(u64, Word, MerklePath)> = paths.into_iter().collect();

        let roots: BTreeSet<RpoDigest> = paths
            .iter()
            .map(|(index, node, path)| path.compute_root(*index, *node).into())
            .collect();

        if roots.len() != 1 {
            return Err(MerkleError::ConflictingRoots(
                roots.iter().map(|v| Word::from(*v)).collect(),
            ));
        }

        for (index_value, node, path) in paths {
            self.add_merkle_path(index_value, node, path)?;
        }

        Ok(roots.iter().next().unwrap().into())
    }

    /// Appends the provided [MerklePathSet] into the store.
    ///
    /// For further reference, check [MerkleStore::add_merkle_path].
    pub fn add_merkle_path_set(&mut self, path_set: &MerklePathSet) -> Result<Word, MerkleError> {
        let root = path_set.root();
        for (index, path) in path_set.to_paths() {
            self.add_merkle_path(index, path.value, path.path)?;
        }
        Ok(root)
    }

    /// Sets a node to `value`.
    ///
    /// # Errors
    ///
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the store.
    pub fn set_node(
        &mut self,
        mut root: Word,
        index: NodeIndex,
        value: Word,
    ) -> Result<RootPath, MerkleError> {
        let node = value;
        let ValuePath { value, path } = self.get_path(root, index)?;

        // performs the update only if the node value differs from the opening
        if node != value {
            root = self.add_merkle_path(index.value(), node, path.clone())?;
        }

        Ok(RootPath { root, path })
    }

    pub fn merge_roots(&mut self, root1: Word, root2: Word) -> Result<Word, MerkleError> {
        let root1: RpoDigest = root1.into();
        let root2: RpoDigest = root2.into();

        if !self.nodes.contains_key(&root1) {
            Err(MerkleError::NodeNotInStore(
                root1.into(),
                NodeIndex::new(0, 0),
            ))
        } else if !self.nodes.contains_key(&root1) {
            Err(MerkleError::NodeNotInStore(
                root2.into(),
                NodeIndex::new(0, 0),
            ))
        } else {
            let parent: Word = Rpo256::merge(&[root1, root2]).into();
            self.nodes.insert(
                parent.into(),
                Node {
                    left: root1,
                    right: root2,
                },
            );

            Ok(parent)
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Node {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.left.write_into(target);
        self.right.write_into(target);
    }
}

impl Deserializable for Node {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let left = RpoDigest::read_from(source)?;
        let right = RpoDigest::read_from(source)?;
        Ok(Node { left, right })
    }
}

impl Serializable for MerkleStore {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.nodes.len() as u64);

        for (k, v) in self.nodes.iter() {
            k.write_into(target);
            v.write_into(target);
        }
    }
}

impl Deserializable for MerkleStore {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_u64()?;
        let mut nodes: BTreeMap<RpoDigest, Node> = BTreeMap::new();

        for _ in 0..len {
            let key = RpoDigest::read_from(source)?;
            let value = Node::read_from(source)?;
            nodes.insert(key, value);
        }

        Ok(MerkleStore { nodes })
    }
}
