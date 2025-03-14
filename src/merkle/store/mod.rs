use alloc::{collections::BTreeMap, vec::Vec};
use core::borrow::Borrow;

use super::{
    EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, MerkleTree, NodeIndex,
    PartialMerkleTree, RootPath, Rpo256, RpoDigest, SimpleSmt, Smt, ValuePath, mmr::Mmr,
};
use crate::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    collections::{KvMap, RecordingMap},
};

#[cfg(test)]
mod tests;

// MERKLE STORE
// ================================================================================================

/// A default [MerkleStore] which uses a simple [BTreeMap] as the backing storage.
pub type DefaultMerkleStore = MerkleStore<BTreeMap<RpoDigest, StoreNode>>;

/// A [MerkleStore] with recording capabilities which uses [RecordingMap] as the backing storage.
pub type RecordingMerkleStore = MerkleStore<RecordingMap<RpoDigest, StoreNode>>;

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StoreNode {
    left: RpoDigest,
    right: RpoDigest,
}

/// An in-memory data store for Merkelized data.
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
/// let mut store: MerkleStore = MerkleStore::new();
///
/// // the store is initialized with the SMT empty nodes
/// assert_eq!(store.num_internal_nodes(), 255);
///
/// let tree1 = MerkleTree::new(vec![A, B, C, D, E, F, G, H0]).unwrap();
/// let tree2 = MerkleTree::new(vec![A, B, C, D, E, F, G, H1]).unwrap();
///
/// // populates the store with two merkle trees, common nodes are shared
/// store.extend(tree1.inner_nodes());
/// store.extend(tree2.inner_nodes());
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
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MerkleStore<T: KvMap<RpoDigest, StoreNode> = BTreeMap<RpoDigest, StoreNode>> {
    nodes: T,
}

impl<T: KvMap<RpoDigest, StoreNode>> Default for MerkleStore<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: KvMap<RpoDigest, StoreNode>> MerkleStore<T> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an empty `MerkleStore` instance.
    pub fn new() -> MerkleStore<T> {
        // pre-populate the store with the empty hashes
        let nodes = empty_hashes().into_iter().collect();
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
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    pub fn get_node(&self, root: RpoDigest, index: NodeIndex) -> Result<RpoDigest, MerkleError> {
        let mut hash = root;

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash))?;

        for i in (0..index.depth()).rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeIndexNotFoundInStore(hash, index))?;

            let bit = (index.value() >> i) & 1;
            hash = if bit == 0 { node.left } else { node.right }
        }

        Ok(hash)
    }

    /// Returns the node at the specified `index` and its opening to the `root`.
    ///
    /// The path starts at the sibling of the target leaf.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    pub fn get_path(&self, root: RpoDigest, index: NodeIndex) -> Result<ValuePath, MerkleError> {
        let mut hash = root;
        let mut path = Vec::with_capacity(index.depth().into());

        // corner case: check the root is in the store when called with index `NodeIndex::root()`
        self.nodes.get(&hash).ok_or(MerkleError::RootNotInStore(hash))?;

        for i in (0..index.depth()).rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeIndexNotFoundInStore(hash, index))?;

            let bit = (index.value() >> i) & 1;
            hash = if bit == 0 {
                path.push(node.right);
                node.left
            } else {
                path.push(node.left);
                node.right
            }
        }

        // the path is computed from root to leaf, so it must be reversed
        path.reverse();

        Ok(ValuePath::new(hash, MerklePath::new(path)))
    }

    // LEAF TRAVERSAL
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of the first leaf or an empty node encountered while traversing the tree
    /// from the specified root down according to the provided index.
    ///
    /// The `tree_depth` parameter specifies the depth of the tree rooted at `root`. The
    /// maximum value the argument accepts is [u64::BITS].
    ///
    /// # Errors
    /// Will return an error if:
    /// - The provided root is not found.
    /// - The provided `tree_depth` is greater than 64.
    /// - The provided `index` is not valid for a depth equivalent to `tree_depth`.
    /// - No leaf or an empty node was found while traversing the tree down to `tree_depth`.
    pub fn get_leaf_depth(
        &self,
        root: RpoDigest,
        tree_depth: u8,
        index: u64,
    ) -> Result<u8, MerkleError> {
        // validate depth and index
        if tree_depth > 64 {
            return Err(MerkleError::DepthTooBig(tree_depth as u64));
        }
        NodeIndex::new(tree_depth, index)?;

        // check if the root exists, providing the proper error report if it doesn't
        let empty = EmptySubtreeRoots::empty_hashes(tree_depth);
        let mut hash = root;
        if !self.nodes.contains_key(&hash) {
            return Err(MerkleError::RootNotInStore(hash));
        }

        // we traverse from root to leaf, so the path is reversed
        let mut path = (index << (64 - tree_depth)).reverse_bits();

        // iterate every depth and reconstruct the path from root to leaf
        for depth in 0..=tree_depth {
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

        // return an error because we exhausted the index but didn't find either a leaf or an
        // empty node
        Err(MerkleError::DepthTooBig(tree_depth as u64 + 1))
    }

    /// Returns index and value of a leaf node which is the only leaf node in a subtree defined by
    /// the provided root. If the subtree contains zero or more than one leaf nodes None is
    /// returned.
    ///
    /// The `tree_depth` parameter specifies the depth of the parent tree such that `root` is
    /// located in this tree at `root_index`. The maximum value the argument accepts is
    /// [u64::BITS].
    ///
    /// # Errors
    /// Will return an error if:
    /// - The provided root is not found.
    /// - The provided `tree_depth` is greater than 64.
    /// - The provided `root_index` has depth greater than `tree_depth`.
    /// - A lone node at depth `tree_depth` is not a leaf node.
    pub fn find_lone_leaf(
        &self,
        root: RpoDigest,
        root_index: NodeIndex,
        tree_depth: u8,
    ) -> Result<Option<(NodeIndex, RpoDigest)>, MerkleError> {
        // we set max depth at u64::BITS as this is the largest meaningful value for a 64-bit index
        const MAX_DEPTH: u8 = u64::BITS as u8;
        if tree_depth > MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(tree_depth as u64));
        }
        let empty = EmptySubtreeRoots::empty_hashes(MAX_DEPTH);

        let mut node = root;
        if !self.nodes.contains_key(&node) {
            return Err(MerkleError::RootNotInStore(node));
        }

        let mut index = root_index;
        if index.depth() > tree_depth {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        }

        // traverse down following the path of single non-empty nodes; this works because if a
        // node has two empty children it cannot contain a lone leaf. similarly if a node has
        // two non-empty children it must contain at least two leaves.
        for depth in index.depth()..tree_depth {
            // if the node is a leaf, return; otherwise, examine the node's children
            let children = match self.nodes.get(&node) {
                Some(node) => node,
                None => return Ok(Some((index, node))),
            };

            let empty_node = empty[depth as usize + 1];
            node = if children.left != empty_node && children.right == empty_node {
                index = index.left_child();
                children.left
            } else if children.left == empty_node && children.right != empty_node {
                index = index.right_child();
                children.right
            } else {
                return Ok(None);
            };
        }

        // if we are here, we got to `tree_depth`; thus, either the current node is a leaf node,
        // and so we return it, or it is an internal node, and then we return an error
        if self.nodes.contains_key(&node) {
            Err(MerkleError::DepthTooBig(tree_depth as u64 + 1))
        } else {
            Ok(Some((index, node)))
        }
    }

    // DATA EXTRACTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a subset of this Merkle store such that the returned Merkle store contains all
    /// nodes which are descendants of the specified roots.
    ///
    /// The roots for which no descendants exist in this Merkle store are ignored.
    pub fn subset<I, R>(&self, roots: I) -> MerkleStore<T>
    where
        I: Iterator<Item = R>,
        R: Borrow<RpoDigest>,
    {
        let mut store = MerkleStore::new();
        for root in roots {
            let root = *root.borrow();
            store.clone_tree_from(root, self);
        }
        store
    }

    /// Iterator over the inner nodes of the [MerkleStore].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.nodes
            .iter()
            .map(|(r, n)| InnerNodeInfo { value: *r, left: n.left, right: n.right })
    }

    /// Iterator over the non-empty leaves of the Merkle tree associated with the specified `root`
    /// and `max_depth`.
    pub fn non_empty_leaves(
        &self,
        root: RpoDigest,
        max_depth: u8,
    ) -> impl Iterator<Item = (NodeIndex, RpoDigest)> + '_ {
        let empty_roots = EmptySubtreeRoots::empty_hashes(max_depth);
        let mut stack = Vec::new();
        stack.push((NodeIndex::new_unchecked(0, 0), root));

        core::iter::from_fn(move || {
            while let Some((index, node_hash)) = stack.pop() {
                // if we are at the max depth then we have reached a leaf
                if index.depth() == max_depth {
                    return Some((index, node_hash));
                }

                // fetch the nodes children and push them onto the stack if they are not the roots
                // of empty subtrees
                if let Some(node) = self.nodes.get(&node_hash) {
                    if !empty_roots.contains(&node.left) {
                        stack.push((index.left_child(), node.left));
                    }
                    if !empty_roots.contains(&node.right) {
                        stack.push((index.right_child(), node.right));
                    }

                // if the node is not in the store assume it is a leaf
                } else {
                    return Some((index, node_hash));
                }
            }

            None
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds all the nodes of a Merkle path represented by `path`, opening to `node`. Returns the
    /// new root.
    ///
    /// This will compute the sibling elements determined by the Merkle `path` and `node`, and
    /// include all the nodes into the store.
    pub fn add_merkle_path(
        &mut self,
        index: u64,
        node: RpoDigest,
        path: MerklePath,
    ) -> Result<RpoDigest, MerkleError> {
        let root = path.inner_nodes(index, node)?.fold(RpoDigest::default(), |_, node| {
            let value: RpoDigest = node.value;
            let left: RpoDigest = node.left;
            let right: RpoDigest = node.right;

            debug_assert_eq!(Rpo256::merge(&[left, right]), value);
            self.nodes.insert(value, StoreNode { left, right });

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
        I: IntoIterator<Item = (u64, RpoDigest, MerklePath)>,
    {
        for (index_value, node, path) in paths.into_iter() {
            self.add_merkle_path(index_value, node, path)?;
        }
        Ok(())
    }

    /// Sets a node to `value`.
    ///
    /// # Errors
    /// This method can return the following errors:
    /// - `RootNotInStore` if the `root` is not present in the store.
    /// - `NodeNotInStore` if a node needed to traverse from `root` to `index` is not present in the
    ///   store.
    pub fn set_node(
        &mut self,
        mut root: RpoDigest,
        index: NodeIndex,
        value: RpoDigest,
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
    pub fn merge_roots(
        &mut self,
        left_root: RpoDigest,
        right_root: RpoDigest,
    ) -> Result<RpoDigest, MerkleError> {
        let parent = Rpo256::merge(&[left_root, right_root]);
        self.nodes.insert(parent, StoreNode { left: left_root, right: right_root });

        Ok(parent)
    }

    // DESTRUCTURING
    // --------------------------------------------------------------------------------------------

    /// Returns the inner storage of this MerkleStore while consuming `self`.
    pub fn into_inner(self) -> T {
        self.nodes
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Recursively clones a tree with the specified root from the specified source into self.
    ///
    /// If the source store does not contain a tree with the specified root, this is a noop.
    fn clone_tree_from(&mut self, root: RpoDigest, source: &Self) {
        // process the node only if it is in the source
        if let Some(node) = source.nodes.get(&root) {
            // if the node has already been inserted, no need to process it further as all of its
            // descendants should be already cloned from the source store
            if self.nodes.insert(root, *node).is_none() {
                self.clone_tree_from(node.left, source);
                self.clone_tree_from(node.right, source);
            }
        }
    }
}

// CONVERSIONS
// ================================================================================================

impl<T: KvMap<RpoDigest, StoreNode>> From<&MerkleTree> for MerkleStore<T> {
    fn from(value: &MerkleTree) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl<T: KvMap<RpoDigest, StoreNode>, const DEPTH: u8> From<&SimpleSmt<DEPTH>> for MerkleStore<T> {
    fn from(value: &SimpleSmt<DEPTH>) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl<T: KvMap<RpoDigest, StoreNode>> From<&Smt> for MerkleStore<T> {
    fn from(value: &Smt) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl<T: KvMap<RpoDigest, StoreNode>> From<&Mmr> for MerkleStore<T> {
    fn from(value: &Mmr) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl<T: KvMap<RpoDigest, StoreNode>> From<&PartialMerkleTree> for MerkleStore<T> {
    fn from(value: &PartialMerkleTree) -> Self {
        let nodes = combine_nodes_with_empty_hashes(value.inner_nodes()).collect();
        Self { nodes }
    }
}

impl<T: KvMap<RpoDigest, StoreNode>> From<T> for MerkleStore<T> {
    fn from(values: T) -> Self {
        let nodes = values.into_iter().chain(empty_hashes()).collect();
        Self { nodes }
    }
}

impl<T: KvMap<RpoDigest, StoreNode>> FromIterator<InnerNodeInfo> for MerkleStore<T> {
    fn from_iter<I: IntoIterator<Item = InnerNodeInfo>>(iter: I) -> Self {
        let nodes = combine_nodes_with_empty_hashes(iter).collect();
        Self { nodes }
    }
}

impl<T: KvMap<RpoDigest, StoreNode>> FromIterator<(RpoDigest, StoreNode)> for MerkleStore<T> {
    fn from_iter<I: IntoIterator<Item = (RpoDigest, StoreNode)>>(iter: I) -> Self {
        let nodes = iter.into_iter().chain(empty_hashes()).collect();
        Self { nodes }
    }
}

// ITERATORS
// ================================================================================================
impl<T: KvMap<RpoDigest, StoreNode>> Extend<InnerNodeInfo> for MerkleStore<T> {
    fn extend<I: IntoIterator<Item = InnerNodeInfo>>(&mut self, iter: I) {
        self.nodes.extend(
            iter.into_iter()
                .map(|info| (info.value, StoreNode { left: info.left, right: info.right })),
        );
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for StoreNode {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.left.write_into(target);
        self.right.write_into(target);
    }
}

impl Deserializable for StoreNode {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let left = RpoDigest::read_from(source)?;
        let right = RpoDigest::read_from(source)?;
        Ok(StoreNode { left, right })
    }
}

impl<T: KvMap<RpoDigest, StoreNode>> Serializable for MerkleStore<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.nodes.len() as u64);

        for (k, v) in self.nodes.iter() {
            k.write_into(target);
            v.write_into(target);
        }
    }
}

impl<T: KvMap<RpoDigest, StoreNode>> Deserializable for MerkleStore<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_u64()?;
        let mut nodes: Vec<(RpoDigest, StoreNode)> = Vec::with_capacity(len as usize);

        for _ in 0..len {
            let key = RpoDigest::read_from(source)?;
            let value = StoreNode::read_from(source)?;
            nodes.push((key, value));
        }

        Ok(nodes.into_iter().collect())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates empty hashes for all the subtrees of a tree with a max depth of 255.
fn empty_hashes() -> impl IntoIterator<Item = (RpoDigest, StoreNode)> {
    let subtrees = EmptySubtreeRoots::empty_hashes(255);
    subtrees
        .iter()
        .rev()
        .copied()
        .zip(subtrees.iter().rev().skip(1).copied())
        .map(|(child, parent)| (parent, StoreNode { left: child, right: child }))
}

/// Consumes an iterator of [InnerNodeInfo] and returns an iterator of `(value, node)` tuples
/// which includes the nodes associate with roots of empty subtrees up to a depth of 255.
fn combine_nodes_with_empty_hashes(
    nodes: impl IntoIterator<Item = InnerNodeInfo>,
) -> impl Iterator<Item = (RpoDigest, StoreNode)> {
    nodes
        .into_iter()
        .map(|info| (info.value, StoreNode { left: info.left, right: info.right }))
        .chain(empty_hashes())
}
