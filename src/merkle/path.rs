use super::{vec, InnerNodeInfo, MerkleError, NodeIndex, Rpo256, Vec, Word};
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

    /// Returns the depth in which this Merkle path proof is valid.
    pub fn depth(&self) -> u8 {
        self.nodes.len() as u8
    }

    /// Computes the merkle root for this opening.
    pub fn compute_root(&self, index: u64, node: Word) -> Result<Word, MerkleError> {
        let mut index = NodeIndex::new(self.depth(), index)?;
        let root = self.nodes.iter().copied().fold(node, |node, sibling| {
            // compute the node and move to the next iteration.
            let input = index.build_node(node.into(), sibling.into());
            index.move_up();
            Rpo256::merge(&input).into()
        });
        Ok(root)
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

    /// Returns an iterator over every inner node of this [MerklePath].
    ///
    /// The iteration order is unspecified.
    ///
    /// # Errors
    /// Returns an error if the specified index is not valid for this path.
    pub fn inner_nodes(&self, index: u64, node: Word) -> Result<InnerNodeIterator, MerkleError> {
        Ok(InnerNodeIterator {
            nodes: &self.nodes,
            index: NodeIndex::new(self.depth(), index)?,
            value: node,
        })
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

// ITERATORS
// ================================================================================================

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

/// An iterator over internal nodes of a [MerklePath].
pub struct InnerNodeIterator<'a> {
    nodes: &'a Vec<Word>,
    index: NodeIndex,
    value: Word,
}

impl<'a> Iterator for InnerNodeIterator<'a> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.index.is_root() {
            let sibling_pos = self.nodes.len() - self.index.depth() as usize;
            let (left, right) = if self.index.is_value_odd() {
                (self.nodes[sibling_pos], self.value)
            } else {
                (self.value, self.nodes[sibling_pos])
            };

            self.value = Rpo256::merge(&[left.into(), right.into()]).into();
            self.index.move_up();

            Some(InnerNodeInfo {
                value: self.value,
                left,
                right,
            })
        } else {
            None
        }
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::merkle::{int_to_node, MerklePath};

    #[test]
    fn test_inner_nodes() {
        let nodes = vec![int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];
        let merkle_path = MerklePath::new(nodes);

        let index = 6;
        let node = int_to_node(5);
        let root = merkle_path.compute_root(index, node).unwrap();

        let inner_root = merkle_path.inner_nodes(index, node).unwrap().last().unwrap().value;

        assert_eq!(root, inner_root);
    }
}
