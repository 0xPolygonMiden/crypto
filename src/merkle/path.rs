use super::{vec, Rpo256, Vec, Word};
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
    pub fn compute_root(&self, mut index: u64, node: Word) -> Word {
        self.nodes.iter().copied().fold(node, |node, sibling| {
            // build the input node, considering the parity of the current index.
            let is_right_sibling = (index & 1) == 1;
            let input = if is_right_sibling {
                [sibling.into(), node.into()]
            } else {
                [node.into(), sibling.into()]
            };
            // compute the node and move to the next iteration.
            index >>= 1;
            Rpo256::merge(&input).into()
        })
    }

    /// Returns the depth in which this Merkle path proof is valid.
    pub fn depth(&self) -> u8 {
        self.nodes.len() as u8
    }

    /// Verifies the Merkle opening proof towards the provided root.
    ///
    /// Returns `true` if `node` exists at `index` in a Merkle tree with `root`.
    pub fn verify(&self, index: u64, node: Word, root: &Word) -> bool {
        root == &self.compute_root(index, node)
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
