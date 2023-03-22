use super::{BTreeMap, MerkleError, MerklePath, NodeIndex, ValuePath, Word, ZERO};

// MERKLE PATH SET
// ================================================================================================

/// A set of Merkle paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePathSet {
    root: Word,
    depth: u8,
    paths: BTreeMap<u64, ValuePath>,
}

impl MerklePathSet {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns an empty MerklePathSet.
    pub fn new(depth: u8) -> Self {
        let root = [ZERO; 4];
        let paths = BTreeMap::new();

        Self { root, depth, paths }
    }

    /// Appends the provided paths iterator into the set.
    ///
    /// Analogous to `[Self::add_path]`.
    pub fn with_paths<I>(self, paths: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = (u64, Word, MerklePath)>,
    {
        paths
            .into_iter()
            .try_fold(self, |mut set, (index, value, path)| {
                set.add_path(index, value, path)?;
                Ok(set)
            })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root to which all paths in this set resolve.
    pub const fn root(&self) -> Word {
        self.root
    }

    /// Returns the depth of the Merkle tree implied by the paths stored in this set.
    ///
    /// Merkle tree of depth 1 has two leaves, depth 2 has four leaves etc.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns all the leaf indexes of this path set.
    pub fn indexes(&self) -> impl Iterator<Item = NodeIndex> + '_ {
        self.paths
            .keys()
            .copied()
            .map(|index| NodeIndex::new(self.depth, index))
    }

    /// Returns a node at the specified index.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The specified index is not valid for the depth of structure.
    /// * Requested node does not exist in the set.
    pub fn get_leaf(&self, index: u64) -> Result<Word, MerkleError> {
        let index = NodeIndex::new(self.depth, index);
        if !index.is_valid() {
            return Err(MerkleError::InvalidIndex(index.with_depth(self.depth)));
        }
        self.paths
            .get(&index.value())
            .map(|p| p.value)
            .ok_or(MerkleError::NodeNotInSet(index.value()))
    }

    /// Returns a Merkle path to the node at the specified index. The node itself is
    /// not included in the path.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The specified index is not valid for the depth of structure.
    /// * Node of the requested path does not exist in the set.
    pub fn get_path(&self, index: u64) -> Result<&MerklePath, MerkleError> {
        let index = NodeIndex::new(self.depth, index);
        if !index.is_valid() {
            return Err(MerkleError::InvalidIndex(index.with_depth(self.depth)));
        }
        self.paths
            .get(&index.value())
            .map(|p| &p.path)
            .ok_or(MerkleError::NodeNotInSet(index.value()))
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the specified Merkle path to this [MerklePathSet]. The `index` and `value` parameters
    /// specify the leaf node at which the path starts.
    ///
    /// The provided path will be a Merkle proof for the leaf, without the root of the tree.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The specified index is is not valid in the context of this Merkle path set (i.e., the
    ///   index implies a greater depth than is specified for this set).
    /// - The specified path is not consistent with other paths in the set (i.e., resolves to a
    ///   different root).
    pub fn add_path(
        &mut self,
        index: u64,
        leaf: Word,
        path: MerklePath,
    ) -> Result<(), MerkleError> {
        let depth = path.len() as u8;
        let index = NodeIndex::new(depth, index);
        if index.depth() != self.depth {
            return Err(MerkleError::InvalidDepth {
                expected: self.depth,
                provided: index.depth(),
            });
        }

        let root = path.compute_root(index.value(), leaf);
        if self.root == Word::default() {
            // a default root will be replaced by the first inserted path
            self.root = root;
        } else if self.root != root {
            // all the paths must open to the same root
            return Err(MerkleError::InvalidPath(path));
        }

        // mutate the internal map
        self.paths
            .insert(index.value(), ValuePath { value: leaf, path });
        Ok(())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash::rpo::Rpo256, merkle::int_to_node};

    #[test]
    fn get_root() {
        let leaf0 = int_to_node(0);
        let leaf1 = int_to_node(1);
        let leaf2 = int_to_node(2);
        let leaf3 = int_to_node(3);

        let parent0 = calculate_parent_hash(leaf0, 0, leaf1);
        let parent1 = calculate_parent_hash(leaf2, 2, leaf3);

        let root_exp = calculate_parent_hash(parent0, 0, parent1);

        let set = super::MerklePathSet::new(2)
            .with_paths([(0, leaf0, vec![leaf1, parent1].into())])
            .unwrap();

        assert_eq!(set.root(), root_exp);
    }

    #[test]
    fn add_and_get_path() {
        let path_6 = vec![int_to_node(7), int_to_node(45), int_to_node(123)];
        let hash_6 = int_to_node(6);
        let index = 6_u64;
        let depth = 3_u8;
        let set = super::MerklePathSet::new(depth)
            .with_paths([(index, hash_6, path_6.clone().into())])
            .unwrap();
        let stored_path_6 = set.get_path(index).unwrap();

        assert_eq!(path_6.as_slice(), stored_path_6.as_slice());
        assert!(set.get_path(15).is_err())
    }

    #[test]
    fn get_node() {
        let path_6 = vec![int_to_node(7), int_to_node(45), int_to_node(123)];
        let hash_6 = int_to_node(6);
        let index = 6_u64;
        let depth = 3_u8;
        let set = MerklePathSet::new(depth)
            .with_paths([(index, hash_6, path_6.into())])
            .unwrap();

        assert_eq!(int_to_node(6u64), set.get_leaf(index).unwrap());
        assert!(set.get_leaf(15).is_err());
    }

    #[test]
    fn depth_3_is_correct() {
        let a = int_to_node(1);
        let b = int_to_node(2);
        let c = int_to_node(3);
        let d = int_to_node(4);
        let e = int_to_node(5);
        let f = int_to_node(6);
        let g = int_to_node(7);
        let h = int_to_node(8);

        let i = Rpo256::merge(&[a.into(), b.into()]);
        let j = Rpo256::merge(&[c.into(), d.into()]);
        let k = Rpo256::merge(&[e.into(), f.into()]);
        let l = Rpo256::merge(&[g.into(), h.into()]);

        let m = Rpo256::merge(&[i.into(), j.into()]);
        let n = Rpo256::merge(&[k.into(), l.into()]);

        let root = Rpo256::merge(&[m.into(), n.into()]);

        let mut set = MerklePathSet::new(3);

        let value = b;
        let index = 1;
        let path = MerklePath::new([a.into(), j.into(), n.into()].to_vec());
        set.add_path(index, value, path.clone()).unwrap();
        assert_eq!(value, set.get_leaf(index).unwrap());
        assert_eq!(Word::from(root), set.root());

        let value = e;
        let index = 4;
        let path = MerklePath::new([f.into(), l.into(), m.into()].to_vec());
        set.add_path(index, value, path.clone()).unwrap();
        assert_eq!(value, set.get_leaf(index).unwrap());
        assert_eq!(Word::from(root), set.root());

        let value = a;
        let index = 0;
        let path = MerklePath::new([b.into(), j.into(), n.into()].to_vec());
        set.add_path(index, value, path.clone()).unwrap();
        assert_eq!(value, set.get_leaf(index).unwrap());
        assert_eq!(Word::from(root), set.root());

        let value = h;
        let index = 7;
        let path = MerklePath::new([g.into(), k.into(), m.into()].to_vec());
        set.add_path(index, value, path.clone()).unwrap();
        assert_eq!(value, set.get_leaf(index).unwrap());
        assert_eq!(Word::from(root), set.root());
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    const fn is_even(pos: u64) -> bool {
        pos & 1 == 0
    }

    /// Calculates the hash of the parent node by two sibling ones
    /// - node — current node
    /// - node_pos — position of the current node
    /// - sibling — neighboring vertex in the tree
    fn calculate_parent_hash(node: Word, node_pos: u64, sibling: Word) -> Word {
        if is_even(node_pos) {
            Rpo256::merge(&[node.into(), sibling.into()]).into()
        } else {
            Rpo256::merge(&[sibling.into(), node.into()]).into()
        }
    }
}
