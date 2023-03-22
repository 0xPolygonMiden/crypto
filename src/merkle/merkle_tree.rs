use super::{Felt, MerkleError, MerklePath, NodeIndex, Rpo256, RpoDigest, Vec, Word};
use crate::{
    utils::{string::String, uninit_vector, word_to_hex},
    FieldElement,
};
use core::{fmt, slice};
use winter_math::log2;

// MERKLE TREE
// ================================================================================================

/// A fully-balanced binary Merkle tree (i.e., a tree where the number of leaves is a power of two).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    pub(crate) nodes: Vec<Word>,
}

impl MerkleTree {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a Merkle tree instantiated from the provided leaves.
    ///
    /// # Errors
    /// Returns an error if the number of leaves is smaller than two or is not a power of two.
    pub fn new(leaves: Vec<Word>) -> Result<Self, MerkleError> {
        let n = leaves.len();
        if n <= 1 {
            return Err(MerkleError::DepthTooSmall(n as u8));
        } else if !n.is_power_of_two() {
            return Err(MerkleError::NumLeavesNotPowerOfTwo(n));
        }

        // create un-initialized vector to hold all tree nodes
        let mut nodes = unsafe { uninit_vector(2 * n) };
        nodes[0] = [Felt::ZERO; 4];

        // copy leaves into the second part of the nodes vector
        nodes[n..].copy_from_slice(&leaves);

        // re-interpret nodes as an array of two nodes fused together
        // Safety: `nodes` will never move here as it is not bound to an external lifetime (i.e.
        // `self`).
        let ptr = nodes.as_ptr() as *const [RpoDigest; 2];
        let pairs = unsafe { slice::from_raw_parts(ptr, n) };

        // calculate all internal tree nodes
        for i in (1..n).rev() {
            nodes[i] = Rpo256::merge(&pairs[i]).into();
        }

        Ok(Self { nodes })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of this Merkle tree.
    pub fn root(&self) -> Word {
        self.nodes[1]
    }

    /// Returns the depth of this Merkle tree.
    ///
    /// Merkle tree of depth 1 has two leaves, depth 2 has four leaves etc.
    pub fn depth(&self) -> u8 {
        log2(self.nodes.len() / 2) as u8
    }

    /// Returns a node at the specified depth and index value.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The specified depth is greater than the depth of the tree.
    /// * The specified index is not valid for the specified depth.
    pub fn get_node(&self, index: NodeIndex) -> Result<Word, MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > self.depth() {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        } else if !index.is_valid() {
            return Err(MerkleError::InvalidIndex(index));
        }

        let pos = index.to_scalar_index() as usize;
        Ok(self.nodes[pos])
    }

    /// Returns a Merkle path to the node at the specified depth and index value. The node itself
    /// is not included in the path.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The specified depth is greater than the depth of the tree.
    /// * The specified value is not valid for the specified depth.
    pub fn get_path(&self, mut index: NodeIndex) -> Result<MerklePath, MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > self.depth() {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        } else if !index.is_valid() {
            return Err(MerkleError::InvalidIndex(index));
        }

        // TODO should we create a helper in `NodeIndex` that will encapsulate traversal to root so
        // we always use inlined `for` instead of `while`? the reason to use `for` is because its
        // easier for the compiler to vectorize.
        let mut path = Vec::with_capacity(index.depth() as usize);
        for _ in 0..index.depth() {
            let sibling = index.sibling().to_scalar_index() as usize;
            path.push(self.nodes[sibling]);
            index.move_up();
        }

        debug_assert!(
            index.is_root(),
            "the path walk must go all the way to the root"
        );

        Ok(path.into())
    }

    /// Replaces the leaf at the specified index with the provided value.
    ///
    /// # Errors
    /// Returns an error if the specified index value is not a valid leaf value for this tree.
    pub fn update_leaf<'a>(&'a mut self, index_value: u64, value: Word) -> Result<(), MerkleError> {
        let depth = self.depth();
        let mut index = NodeIndex::new(depth, index_value);
        if !index.is_valid() {
            return Err(MerkleError::InvalidIndex(index));
        }

        // we don't need to copy the pairs into a new address as we are logically guaranteed to not
        // overlap write instructions. however, it's important to bind the lifetime of pairs to
        // `self.nodes` so the compiler will never move one without moving the other.
        debug_assert_eq!(self.nodes.len() & 1, 0);
        let n = self.nodes.len() / 2;

        // Safety: the length of nodes is guaranteed to contain pairs of words; hence, pairs of
        // digests. we explicitly bind the lifetime here so we add an extra layer of guarantee that
        // `self.nodes` will be moved only if `pairs` is moved as well. also, the algorithm is
        // logically guaranteed to not overlap write positions as the write index is always half
        // the index from which we read the digest input.
        let ptr = self.nodes.as_ptr() as *const [RpoDigest; 2];
        let pairs: &'a [[RpoDigest; 2]] = unsafe { slice::from_raw_parts(ptr, n) };

        // update the current node
        let pos = index.to_scalar_index() as usize;
        self.nodes[pos] = value;

        // traverse to the root, updating each node with the merged values of its parents
        for _ in 0..index.depth() {
            index.move_up();
            let pos = index.to_scalar_index() as usize;
            let value = Rpo256::merge(&pairs[pos]).into();
            self.nodes[pos] = value;
        }

        Ok(())
    }
}

/// Utility to vizualize a [MerkleTree] in text.
pub fn tree_to_text(tree: &MerkleTree) -> Result<String, fmt::Error> {
    let indent = "  ";
    let mut s = String::new();
    s.push_str(&word_to_hex(&tree.root())?);
    s.push('\n');
    for d in 1..=tree.depth() {
        let entries = 2u64.pow(d.into());
        for i in 0..entries {
            let index = NodeIndex::new(d, i);

            let node = tree
                .get_node(index)
                .expect("The index must always be valid");

            for _ in 0..d {
                s.push_str(indent);
            }
            s.push_str(&word_to_hex(&node)?);
            s.push('\n');
        }
    }

    Ok(s)
}

/// Utility to vizualize a [MerklePath] in text.
pub fn path_to_text(path: &MerklePath) -> Result<String, fmt::Error> {
    let mut s = String::new();
    s.push('[');

    for el in path.iter() {
        s.push_str(&word_to_hex(el)?);
        s.push_str(", ");
    }

    // remove the last ", "
    if path.len() != 0 {
        s.pop();
        s.pop();
    }
    s.push(']');

    Ok(s)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::int_to_node;
    use core::mem::size_of;
    use proptest::prelude::*;

    const LEAVES4: [Word; 4] = [
        int_to_node(1),
        int_to_node(2),
        int_to_node(3),
        int_to_node(4),
    ];

    const LEAVES8: [Word; 8] = [
        int_to_node(1),
        int_to_node(2),
        int_to_node(3),
        int_to_node(4),
        int_to_node(5),
        int_to_node(6),
        int_to_node(7),
        int_to_node(8),
    ];

    #[test]
    fn build_merkle_tree() {
        let tree = super::MerkleTree::new(LEAVES4.to_vec()).unwrap();
        assert_eq!(8, tree.nodes.len());

        // leaves were copied correctly
        for (a, b) in tree.nodes.iter().skip(4).zip(LEAVES4.iter()) {
            assert_eq!(a, b);
        }

        let (root, node2, node3) = compute_internal_nodes();

        assert_eq!(root, tree.nodes[1]);
        assert_eq!(node2, tree.nodes[2]);
        assert_eq!(node3, tree.nodes[3]);

        assert_eq!(root, tree.root());
    }

    #[test]
    fn get_leaf() {
        let tree = super::MerkleTree::new(LEAVES4.to_vec()).unwrap();

        // check depth 2
        assert_eq!(LEAVES4[0], tree.get_node(NodeIndex::new(2, 0)).unwrap());
        assert_eq!(LEAVES4[1], tree.get_node(NodeIndex::new(2, 1)).unwrap());
        assert_eq!(LEAVES4[2], tree.get_node(NodeIndex::new(2, 2)).unwrap());
        assert_eq!(LEAVES4[3], tree.get_node(NodeIndex::new(2, 3)).unwrap());

        // check depth 1
        let (_, node2, node3) = compute_internal_nodes();

        assert_eq!(node2, tree.get_node(NodeIndex::new(1, 0)).unwrap());
        assert_eq!(node3, tree.get_node(NodeIndex::new(1, 1)).unwrap());
    }

    #[test]
    fn get_path() {
        let tree = super::MerkleTree::new(LEAVES4.to_vec()).unwrap();

        let (_, node2, node3) = compute_internal_nodes();

        // check depth 2
        assert_eq!(
            vec![LEAVES4[1], node3],
            *tree.get_path(NodeIndex::new(2, 0)).unwrap()
        );
        assert_eq!(
            vec![LEAVES4[0], node3],
            *tree.get_path(NodeIndex::new(2, 1)).unwrap()
        );
        assert_eq!(
            vec![LEAVES4[3], node2],
            *tree.get_path(NodeIndex::new(2, 2)).unwrap()
        );
        assert_eq!(
            vec![LEAVES4[2], node2],
            *tree.get_path(NodeIndex::new(2, 3)).unwrap()
        );

        // check depth 1
        assert_eq!(vec![node3], *tree.get_path(NodeIndex::new(1, 0)).unwrap());
        assert_eq!(vec![node2], *tree.get_path(NodeIndex::new(1, 1)).unwrap());
    }

    #[test]
    fn update_leaf() {
        let mut tree = super::MerkleTree::new(LEAVES8.to_vec()).unwrap();

        // update one leaf
        let value = 3;
        let new_node = int_to_node(9);
        let mut expected_leaves = LEAVES8.to_vec();
        expected_leaves[value as usize] = new_node;
        let expected_tree = super::MerkleTree::new(expected_leaves.clone()).unwrap();

        tree.update_leaf(value, new_node).unwrap();
        assert_eq!(expected_tree.nodes, tree.nodes);

        // update another leaf
        let value = 6;
        let new_node = int_to_node(10);
        expected_leaves[value as usize] = new_node;
        let expected_tree = super::MerkleTree::new(expected_leaves.clone()).unwrap();

        tree.update_leaf(value, new_node).unwrap();
        assert_eq!(expected_tree.nodes, tree.nodes);
    }

    proptest! {
        #[test]
        fn arbitrary_word_can_be_represented_as_digest(
            a in prop::num::u64::ANY,
            b in prop::num::u64::ANY,
            c in prop::num::u64::ANY,
            d in prop::num::u64::ANY,
        ) {
            // this test will assert the memory equivalence between word and digest.
            // it is used to safeguard the `[MerkleTee::update_leaf]` implementation
            // that assumes this equivalence.

            // build a word and copy it to another address as digest
            let word = [Felt::new(a), Felt::new(b), Felt::new(c), Felt::new(d)];
            let digest = RpoDigest::from(word);

            // assert the addresses are different
            let word_ptr = (&word).as_ptr() as *const u8;
            let digest_ptr = (&digest).as_ptr() as *const u8;
            assert_ne!(word_ptr, digest_ptr);

            // compare the bytes representation
            let word_bytes = unsafe { slice::from_raw_parts(word_ptr, size_of::<Word>()) };
            let digest_bytes = unsafe { slice::from_raw_parts(digest_ptr, size_of::<RpoDigest>()) };
            assert_eq!(word_bytes, digest_bytes);
        }
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    fn compute_internal_nodes() -> (Word, Word, Word) {
        let node2 = Rpo256::hash_elements(&[LEAVES4[0], LEAVES4[1]].concat());
        let node3 = Rpo256::hash_elements(&[LEAVES4[2], LEAVES4[3]].concat());
        let root = Rpo256::merge(&[node2, node3]);

        (root.into(), node2.into(), node3.into())
    }
}
