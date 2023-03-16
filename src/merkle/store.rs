//! An in-memory data store for Merkle-lized data
//!
//! This is a in memory data store for Merkle trees, this store allows all the nodes of a tree
//! (leaves or internal) to live as long as necessary and without duplication, this allows the
//! implementation of efficient persistent data structures
use super::{
    BTreeMap, BTreeSet, EmptySubtreeRoots, MerkleError, MerklePath, MerkleTree, NodeIndex, Rpo256,
    RpoDigest, SimpleSmt, Vec, Word,
};

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct Node {
    left: RpoDigest,
    right: RpoDigest,
}

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
        let subtrees = EmptySubtreeRoots::empty_hashes(64);
        let nodes = subtrees
            .iter()
            .copied()
            .zip(subtrees.iter().skip(1).copied())
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

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds all the nodes of a Merkle tree represented by `leaves`.
    ///
    /// This will instantiate a Merkle tree using `leaves` and include all the nodes into the
    /// storage.
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
    /// the storage.
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

    /// Adds all the nodes of a Merkle path represented by `path`.
    ///
    /// This will compute the sibling elements determined by the Merkle `path` and `node`, and
    /// include all the nodes into the storage.
    pub fn add_merkle_path(
        &mut self,
        index_value: u64,
        node: Word,
        path: MerklePath,
    ) -> Result<Word, MerkleError> {
        let mut node = node;
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
    /// into the storage.
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

        // Returns the parent of the last paths (assumes all paths have the same parent) or empty
        // The length of unique_roots is checked above, so this wont panic
        Ok(roots.iter().next().unwrap().into())
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the node at `index` rooted on the tree `root`.
    ///
    /// # Errors
    ///
    /// This will return `NodeNotInStorage` if the element is not present in the store.
    pub fn get_node(&self, root: Word, index: NodeIndex) -> Result<Word, MerkleError> {
        let mut hash: RpoDigest = root.into();

        // Check the root is in the storage when called with `NodeIndex::root()`
        self.nodes
            .get(&hash)
            .ok_or(MerkleError::NodeNotInStorage(hash.into(), index))?;

        for bit in index.bit_iterator().rev() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeNotInStorage(hash.into(), index))?;
            hash = if bit { node.right } else { node.left }
        }

        Ok(hash.into())
    }

    /// Returns the path for the node at `index` rooted on the tree `root`.
    ///
    /// # Errors
    ///
    /// This will return `NodeNotInStorage` if the element is not present in the store.
    pub fn get_path(
        &self,
        root: Word,
        index: NodeIndex,
    ) -> Result<(Word, MerklePath), MerkleError> {
        let mut hash: RpoDigest = root.into();
        let mut path = Vec::new();
        let node = RpoDigest::default();
        for bit in index.bit_iterator() {
            let node = self
                .nodes
                .get(&hash)
                .ok_or(MerkleError::NodeNotInStorage(hash.into(), index))?;

            hash = if bit {
                path.push(node.left.into());
                node.right
            } else {
                path.push(node.right.into());
                node.left
            }
        }

        Ok((node.into(), MerklePath::new(path)))
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    pub fn set_node(
        &mut self,
        root: Word,
        index: NodeIndex,
        value: Word,
    ) -> Result<Word, MerkleError> {
        let (current_node, path) = self.get_path(root, index)?;
        if current_node != value {
            self.add_merkle_path(index.value(), value, path)
        } else {
            Ok(root)
        }
    }

    pub fn merge_roots(&mut self, root1: Word, root2: Word) -> Result<Word, MerkleError> {
        let root1: RpoDigest = root1.into();
        let root2: RpoDigest = root2.into();

        if !self.nodes.contains_key(&root1) {
            Err(MerkleError::NodeNotInStorage(
                root1.into(),
                NodeIndex::new(0, 0),
            ))
        } else if !self.nodes.contains_key(&root1) {
            Err(MerkleError::NodeNotInStorage(
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

#[cfg(test)]
mod test {
    use super::{MerkleError, MerkleStore, MerkleTree, NodeIndex, SimpleSmt, Word};
    use crate::merkle::int_to_node;
    use crate::merkle::MerklePathSet;

    const KEYS4: [u64; 4] = [0, 1, 2, 3];
    const LEAVES4: [Word; 4] = [
        int_to_node(1),
        int_to_node(2),
        int_to_node(3),
        int_to_node(4),
    ];

    #[test]
    fn test_add_merkle_tree() -> Result<(), MerkleError> {
        let mut store = MerkleStore::default();

        let mtree = MerkleTree::new(LEAVES4.to_vec())?;
        store.add_merkle_tree(LEAVES4.to_vec())?;

        assert!(
            store
                .get_node(mtree.root(), NodeIndex::new(mtree.depth(), 0))
                .is_ok(),
            "node 0 must be in the tree"
        );
        assert!(
            store
                .get_node(mtree.root(), NodeIndex::new(mtree.depth(), 1))
                .is_ok(),
            "node 1 must be in the tree"
        );
        assert!(
            store
                .get_node(mtree.root(), NodeIndex::new(mtree.depth(), 2))
                .is_ok(),
            "node 2 must be in the tree"
        );
        assert!(
            store
                .get_node(mtree.root(), NodeIndex::new(mtree.depth(), 3))
                .is_ok(),
            "node 3 must be in the tree"
        );

        store
            .get_node(mtree.root(), NodeIndex::new(mtree.depth(), 0))
            .expect("node 0 must be in tree");
        store
            .get_node(mtree.root(), NodeIndex::new(mtree.depth(), 1))
            .expect("node 1 must be in tree");
        store
            .get_node(mtree.root(), NodeIndex::new(mtree.depth(), 2))
            .expect("node 2 must be in tree");
        store
            .get_node(mtree.root(), NodeIndex::new(mtree.depth(), 3))
            .expect("node 3 must be in tree");

        Ok(())
    }

    #[test]
    fn test_get_invalid_node() {
        let mut store = MerkleStore::default();
        let mtree = MerkleTree::new(LEAVES4.to_vec()).expect("creating a merkle tree must work");
        store
            .add_merkle_tree(LEAVES4.to_vec())
            .expect("adding a merkle tree to the store must work");
        let _ = store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 3));
    }

    #[test]
    fn test_add_sparse_merkle_tree_one_level() -> Result<(), MerkleError> {
        let mut store = MerkleStore::default();
        let keys2: [u64; 2] = [0, 1];
        let leaves2: [Word; 2] = [int_to_node(1), int_to_node(2)];
        store.add_sparse_merkle_tree(keys2.into_iter().zip(leaves2.into_iter()))?;
        let smt = SimpleSmt::new(SimpleSmt::MAX_DEPTH)
            .unwrap()
            .with_leaves(keys2.into_iter().zip(leaves2.into_iter()))
            .unwrap();

        let idx = NodeIndex::new(1, 0);
        assert_eq!(
            store.get_node(smt.root(), idx).unwrap(),
            smt.get_node(&idx).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_add_sparse_merkle_tree() -> Result<(), MerkleError> {
        let mut store = MerkleStore::default();
        store.add_sparse_merkle_tree(KEYS4.into_iter().zip(LEAVES4.into_iter()))?;

        let smt = SimpleSmt::new(SimpleSmt::MAX_DEPTH)
            .unwrap()
            .with_leaves(KEYS4.into_iter().zip(LEAVES4.into_iter()))
            .unwrap();

        let idx = NodeIndex::new(1, 0);
        assert_eq!(
            store.get_node(smt.root(), idx).unwrap(),
            smt.get_node(&idx).unwrap()
        );
        let idx = NodeIndex::new(1, 1);
        assert_eq!(
            store.get_node(smt.root(), idx).unwrap(),
            smt.get_node(&idx).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_add_merkle_paths() -> Result<(), MerkleError> {
        let mut store = MerkleStore::default();
        let mtree = MerkleTree::new(LEAVES4.to_vec())?;

        let i0 = 0;
        let p0 = mtree.get_path(NodeIndex::new(2, i0)).unwrap();

        let i1 = 1;
        let p1 = mtree.get_path(NodeIndex::new(2, i1)).unwrap();

        let i2 = 2;
        let p2 = mtree.get_path(NodeIndex::new(2, i2)).unwrap();

        let i3 = 3;
        let p3 = mtree.get_path(NodeIndex::new(2, i3)).unwrap();

        let paths = [
            (i0, LEAVES4[i0 as usize], p0),
            (i1, LEAVES4[i1 as usize], p1),
            (i2, LEAVES4[i2 as usize], p2),
            (i3, LEAVES4[i3 as usize], p3),
        ];

        store
            .add_merkle_paths(paths.clone())
            .expect("the valid paths must work");

        let set = MerklePathSet::new(3).with_paths(paths).unwrap();

        assert_eq!(
            set.get_node(NodeIndex::new(3, 0)).unwrap(),
            store.get_node(set.root(), NodeIndex::new(2, 0b00)).unwrap(),
        );
        assert_eq!(
            set.get_node(NodeIndex::new(3, 1)).unwrap(),
            store.get_node(set.root(), NodeIndex::new(2, 0b01)).unwrap(),
        );
        assert_eq!(
            set.get_node(NodeIndex::new(3, 2)).unwrap(),
            store.get_node(set.root(), NodeIndex::new(2, 0b10)).unwrap(),
        );
        assert_eq!(
            set.get_node(NodeIndex::new(3, 3)).unwrap(),
            store.get_node(set.root(), NodeIndex::new(2, 0b11)).unwrap(),
        );

        Ok(())
    }
}
