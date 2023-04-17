use super::{vec, MerkleError, NodeIndex, Rpo256, RpoDigest, Vec, Word};
use core::ops::{Deref, DerefMut};

// MERKLE PATH
// ================================================================================================

/// A merkle path container, composed of a sequence of nodes of a Merkle tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MerklePath {
    nodes: Vec<Word>,
}

impl MerklePath {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new Merkle path from a list of nodes.
    pub fn new(nodes: Vec<Word>) -> Self {
        Self { nodes }
    }

    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Computes the merkle root for this opening.
    pub fn compute_root(&self, index: u64, node: Word) -> Result<Word, MerkleError> {
        let index = NodeIndex::new(self.depth(), index)?;
        let root = self.compute_parents(index, node).last().unwrap_or(node);
        Ok(root)
    }

    /// Returns an iterator that will traverse from the leaf towards the root, yielding the parent
    /// of node for every iteration.
    pub fn compute_parents(&self, index: NodeIndex, node: Word) -> impl Iterator<Item = Word> + '_ {
        struct State {
            index: NodeIndex,
            curr_node: RpoDigest,
        }

        self.nodes.iter().copied().scan(
            State {
                index,
                curr_node: node.into(),
            },
            |state, sibling| {
                // compute the node and move to the next iteration.
                let input = state.index.build_node(state.curr_node, sibling.into());
                state.index.move_up();
                state.curr_node = Rpo256::merge(&input);
                Some(state.curr_node.into())
            },
        )
    }

    /// Returns the depth in which this Merkle path proof is valid.
    pub fn depth(&self) -> u8 {
        self.nodes.len() as u8
    }

    /// Verifies the Merkle opening proof towards the provided root.
    ///
    /// Returns `true` if `node` exists at `index` in a Merkle tree with `root`.
    pub fn verify(&self, index: u64, node: Word, root: &Word) -> bool {
        match self.compute_root(index, node) {
            Ok(computed_root) => root == &computed_root,
            Err(_) => false,
        }
    }
}

impl From<Vec<Word>> for MerklePath {
    fn from(path: Vec<Word>) -> Self {
        Self::new(path)
    }
}

impl Deref for MerklePath {
    // we use `Vec` here instead of slice so we can call vector mutation methods directly from the
    // merkle path (example: `Vec::remove`).
    type Target = Vec<Word>;

    fn deref(&self) -> &Self::Target {
        &self.nodes
    }
}

impl DerefMut for MerklePath {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.nodes
    }
}

impl FromIterator<Word> for MerklePath {
    fn from_iter<T: IntoIterator<Item = Word>>(iter: T) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

impl IntoIterator for MerklePath {
    type Item = Word;
    type IntoIter = vec::IntoIter<Word>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.into_iter()
    }
}

// MERKLE PATH CONTAINERS
// ================================================================================================

/// A container for a [Word] value and its [MerklePath] opening.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValuePath {
    /// The node value opening for `path`.
    pub value: Word,
    /// The path from `value` to `root` (exclusive).
    pub path: MerklePath,
}

/// A container for a [MerklePath] and its [Word] root.
///
/// This structure does not provide any guarantees regarding the correctness of the path to the
/// root. For more information, check [MerklePath::verify].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootPath {
    /// The node value opening for `path`.
    pub root: Word,
    /// The path from `value` to `root` (exclusive).
    pub path: MerklePath,
}

#[cfg(test)]
mod test {
    use crate::merkle::{int_to_node, MerklePath, NodeIndex, Rpo256, Vec, Word};

    #[test]
    fn test_merkle_path_empty() {
        let node0 = int_to_node(5);
        let parents: &[Word] = &[];

        let merkle_path = MerklePath::new(vec![]);
        let computed: Vec<_> = merkle_path
            .compute_parents(NodeIndex::new(merkle_path.depth(), 0).unwrap(), node0)
            .collect();

        assert!(merkle_path.verify(0, node0, &node0));
        assert_eq!(&computed, parents);
    }

    #[test]
    fn test_merkle_path_left_most_element() {
        let siblings = [int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];
        let node0 = int_to_node(5);
        let parent1: Word = Rpo256::hash_elements(&[node0, siblings[0]].concat()).into();
        let parent2: Word = Rpo256::hash_elements(&[parent1, siblings[1]].concat()).into();
        let parent3: Word = Rpo256::hash_elements(&[parent2, siblings[2]].concat()).into();
        let root: Word = Rpo256::hash_elements(&[parent3, siblings[3]].concat()).into();
        let parents = &[parent1, parent2, parent3, root];

        let merkle_path = MerklePath::new(siblings.to_vec());
        let computed: Vec<_> = merkle_path
            .compute_parents(NodeIndex::new(merkle_path.depth(), 0).unwrap(), node0)
            .collect();

        assert!(merkle_path.verify(0, node0, &root));
        assert_eq!(&computed, parents);
    }

    #[test]
    fn test_merkle_path_right_left_right_left_element() {
        let siblings = [int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];
        let node0 = int_to_node(5);
        let parent1: Word = Rpo256::hash_elements(&[siblings[0], node0].concat()).into();
        let parent2: Word = Rpo256::hash_elements(&[parent1, siblings[1]].concat()).into();
        let parent3: Word = Rpo256::hash_elements(&[siblings[2], parent2].concat()).into();
        let root: Word = Rpo256::hash_elements(&[parent3, siblings[3]].concat()).into();
        let parents = &[parent1, parent2, parent3, root];

        let merkle_path = MerklePath::new(siblings.to_vec());
        let computed: Vec<_> = merkle_path
            .compute_parents(NodeIndex::new(merkle_path.depth(), 0b0101).unwrap(), node0)
            .collect();

        assert_eq!(&computed, parents);
        assert!(merkle_path.verify(0b0101, node0, &root));
    }

    #[test]
    fn test_merkle_path_right_most_element() {
        let siblings = [int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];
        let node0 = int_to_node(5);
        let parent1: Word = Rpo256::hash_elements(&[siblings[0], node0].concat()).into();
        let parent2: Word = Rpo256::hash_elements(&[siblings[1], parent1].concat()).into();
        let parent3: Word = Rpo256::hash_elements(&[siblings[2], parent2].concat()).into();
        let root: Word = Rpo256::hash_elements(&[siblings[3], parent3].concat()).into();
        let parents = &[parent1, parent2, parent3, root];

        let merkle_path = MerklePath::new(siblings.to_vec());
        let computed: Vec<_> = merkle_path
            .compute_parents(NodeIndex::new(merkle_path.depth(), 15).unwrap(), node0)
            .collect();

        assert_eq!(&computed, parents);
        assert!(merkle_path.verify(15, node0, &root));
    }
}
