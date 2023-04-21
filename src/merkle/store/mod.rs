use super::mmr::Mmr;
use super::{
    BTreeMap, EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, MerklePathSet, MerkleTree,
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
/// let tree1 = MerkleTree::new(vec![A, B, C, D, E, F, G, H0]).unwrap();
/// let tree2 = MerkleTree::new(vec![A, B, C, D, E, F, G, H1]).unwrap();
///
/// // populates the store with two merkle trees, common nodes are shared
/// store
///     .extend(tree1.inner_nodes())
///     .extend(tree2.inner_nodes());
///
/// // every leaf except the last are the same
/// for i in 0..7 {
///     let idx0 = NodeIndex::new(3, i).unwrap();
///     let d0 = store.get_node(ROOT0, idx0).unwrap();
///     let idx1 = NodeIndex::new(3, i).unwrap();
///     let d1 = store.get_node(ROOT1, idx1).unwrap();
///     assert_eq!(d0, d1, "Both trees have the same leaf at pos {i}");
/// }
///
/// // The leafs A-B-C-D are the same for both trees, so are their 2 immediate parents
/// for i in 0..4 {
///     let idx0 = NodeIndex::new(3, i).unwrap();
///     let d0 = store.get_path(ROOT0, idx0).unwrap();
///     let idx1 = NodeIndex::new(3, i).unwrap();
///     let d1 = store.get_path(ROOT1, idx1).unwrap();
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
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash.into()))?;

        for i in (0..index.depth()).rev() {
            let node =
                self.nodes.get(&hash).ok_or(MerkleError::NodeNotInStore(hash.into(), index))?;

            let bit = (index.value() >> i) & 1;
            hash = if bit == 0 { node.left } else { node.right }
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
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash.into()))?;

        for i in (0..index.depth()).rev() {
            let node =
                self.nodes.get(&hash).ok_or(MerkleError::NodeNotInStore(hash.into(), index))?;

            let bit = (index.value() >> i) & 1;
            hash = if bit == 0 {
                path.push(node.right.into());
                node.left
            } else {
                path.push(node.left.into());
                node.right
            }
        }

        // the path is computed from root to leaf, so it must be reversed
        path.reverse();

        Ok(ValuePath {
            value: hash.into(),
            path: MerklePath::new(path),
        })
    }

    /// Reconstructs a path from the root until a leaf or empty node and returns its depth.
    ///
    /// The `tree_depth` parameter defines up to which depth the tree will be traversed, starting
    /// from `root`. The maximum value the argument accepts is [u64::BITS].
    ///
    /// The traversed path from leaf to root will start at the least significant bit of `index`,
    /// and will be executed for `tree_depth` bits.
    ///
    /// # Errors
    /// Will return an error if:
    /// - The provided root is not found.
    /// - The path from the root continues to a depth greater than `tree_depth`.
    /// - The provided `tree_depth` is greater than `64.
    /// - The provided `index` is not valid for a depth equivalent to `tree_depth`. For more
    /// information, check [NodeIndex::new].
    pub fn get_leaf_depth(
        &self,
        root: Word,
        tree_depth: u8,
        index: u64,
    ) -> Result<u8, MerkleError> {
        // validate depth and index
        if tree_depth > 64 {
            return Err(MerkleError::DepthTooBig(tree_depth as u64));
        }
        NodeIndex::new(tree_depth, index)?;

        // it's not illegal to have a maximum depth of `0`; we should just return the root in that
        // case. this check will simplify the implementation as we could overflow bits for depth
        // `0`.
        if tree_depth == 0 {
            return Ok(0);
        }

        // check if the root exists, providing the proper error report if it doesn't
        let empty = EmptySubtreeRoots::empty_hashes(tree_depth);
        let mut hash: RpoDigest = root.into();
        if !self.nodes.contains_key(&hash) {
            return Err(MerkleError::RootNotInStore(hash.into()));
        }

        // we traverse from root to leaf, so the path is reversed
        let mut path = (index << (64 - tree_depth)).reverse_bits();

        // iterate every depth and reconstruct the path from root to leaf
        for depth in 0..tree_depth {
            // we short-circuit if an empty node has been found
            if hash == empty[depth as usize] {
                return Ok(depth);
            }

            // fetch the children pair, mapped by its parent hash
            let children = match self.nodes.get(&hash) {
                Some(node) => node,
                None => return Ok(depth),
            };

            // traverse down
            hash = if path & 1 == 0 { children.left } else { children.right };
            path >>= 1;
        }

        // at max depth assert it doesn't have sub-trees
        if self.nodes.contains_key(&hash) {
            return Err(MerkleError::DepthTooBig(tree_depth as u64 + 1));
        }

        // depleted bits; return max depth
        Ok(tree_depth)
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds a sequence of nodes yielded by the provided iterator into the store.
    pub fn extend<I>(&mut self, iter: I) -> &mut MerkleStore
    where
        I: Iterator<Item = InnerNodeInfo>,
    {
        for node in iter {
            let value: RpoDigest = node.value.into();
            let left: RpoDigest = node.left.into();
            let right: RpoDigest = node.right.into();

            debug_assert_eq!(Rpo256::merge(&[left, right]), value);
            self.nodes.insert(value, Node { left, right });
        }

        self
    }

    /// Adds all the nodes of a Merkle path represented by `path`, opening to `node`. Returns the
    /// new root.
    ///
    /// This will compute the sibling elements determined by the Merkle `path` and `node`, and
    /// include all the nodes into the store.
    pub fn add_merkle_path(
        &mut self,
        index: u64,
        node: Word,
        path: MerklePath,
    ) -> Result<Word, MerkleError> {
        let root = path.inner_nodes(index, node)?.fold(Word::default(), |_, node| {
            let value: RpoDigest = node.value.into();
            let left: RpoDigest = node.left.into();
            let right: RpoDigest = node.right.into();

            debug_assert_eq!(Rpo256::merge(&[left, right]), value);
            self.nodes.insert(value, Node { left, right });

            node.value
        });
        Ok(root)
    }

    /// Adds all the nodes of multiple Merkle paths into the store.
    ///
    /// This will compute the sibling elements for each Merkle `path` and include all the nodes
    /// into the store.
    ///
    /// For further reference, check [MerkleStore::add_merkle_path].
    pub fn add_merkle_paths<I>(&mut self, paths: I) -> Result<(), MerkleError>
    where
        I: IntoIterator<Item = (u64, Word, MerklePath)>,
    {
        for (index_value, node, path) in paths.into_iter() {
            self.add_merkle_path(index_value, node, path)?;
        }
        Ok(())
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

    /// Merges two elements and adds the resulting node into the store.
    ///
    /// Merges arbitrary values. They may be leafs, nodes, or a mixture of both.
    pub fn merge_roots(&mut self, root1: Word, root2: Word) -> Result<Word, MerkleError> {
        let left: RpoDigest = root1.into();
        let right: RpoDigest = root2.into();

        let parent = Rpo256::merge(&[left, right]);
        self.nodes.insert(parent, Node { left, right });

        Ok(parent.into())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<&MerkleTree> for MerkleStore {
    fn from(value: &MerkleTree) -> Self {
        let mut store = MerkleStore::new();
        store.extend(value.inner_nodes());
        store
    }
}

impl From<&SimpleSmt> for MerkleStore {
    fn from(value: &SimpleSmt) -> Self {
        let mut store = MerkleStore::new();
        store.extend(value.inner_nodes());
        store
    }
}

impl From<&Mmr> for MerkleStore {
    fn from(value: &Mmr) -> Self {
        let mut store = MerkleStore::new();
        store.extend(value.inner_nodes());
        store
    }
}

impl FromIterator<InnerNodeInfo> for MerkleStore {
    fn from_iter<T: IntoIterator<Item = InnerNodeInfo>>(iter: T) -> Self {
        let mut store = MerkleStore::new();
        store.extend(iter.into_iter());
        store
    }
}

// ITERATORS
// ================================================================================================

impl Extend<InnerNodeInfo> for MerkleStore {
    fn extend<T: IntoIterator<Item = InnerNodeInfo>>(&mut self, iter: T) {
        self.extend(iter.into_iter());
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
