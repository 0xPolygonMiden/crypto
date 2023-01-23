use super::{vec, BTreeMap, Felt, Rpo256, RpoDigest, StarkField, Vec, Word, WORD_SIZE, ZERO};
use core::borrow::Borrow;

mod constants;
pub use constants::EMPTY_SUBTREES;

mod index;
pub use index::{CanonicalWord, LeafIndex, NodeIndex};

mod leaf;
pub use leaf::Leaf;

mod path;
pub use path::MerklePath;

mod proof;
pub use proof::{LeafProof, LeafProofInput};

mod storage;
pub use storage::{Storage, StorageError};

#[cfg(test)]
mod tests;

// TIERED SPARSE MERKLE TREE
// ================================================================================================

/// A tiered sparse Merkle tree.
///
/// The leaves will be inserted only in predefined depths, and will compose an ordered list of
/// leaves if the collide at the maximum depth of the tree.
pub struct TieredSmt {
    root: Word,
    storage: Storage,
}

impl TieredSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Maximum depth where leaves will be ordered into lists if they collide.
    pub const MAX_DEPTH: u8 = 64;

    /// Node depth of each tier.
    pub const TIER_DEPTH: u8 = 16;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of the tiered sparse Merkle tree with the provided storage backend.
    pub fn with_storage(storage: Storage) -> Result<Self, StorageError> {
        let root = Word::default();
        let mut tree = Self { root, storage };
        tree.root = tree.get_node(&NodeIndex::root())?;
        Ok(tree)
    }

    /// Mutates the tiered sparse Merkle tree, extending its leaves set with the provided argument.
    pub fn with_leaves<I, T>(self, leaves: I) -> Result<Self, StorageError>
    where
        I: IntoIterator<Item = (Word, Word)>,
        Leaf: From<T>,
    {
        leaves.into_iter().try_fold(self, |mut tree, (key, value)| {
            tree.insert(key, value)?;
            Ok(tree)
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a leaf value indexed by the provided key.
    pub fn get_leaf_value<K>(&self, key: K) -> Result<Option<Word>, StorageError>
    where
        CanonicalWord: From<K>,
    {
        let key = CanonicalWord::from(key);
        self.storage.get_leaf_value(&key)
    }

    /// Returns the current Merkle root of the state of the tree.
    pub const fn root(&self) -> &Word {
        &self.root
    }

    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Fetch a tree node, returning an empty sub-tree constant if absent.
    pub fn get_node(&self, index: &NodeIndex) -> Result<Word, StorageError> {
        debug_assert!(index.depth() <= Self::MAX_DEPTH);
        let node = self
            .storage
            .get_node(index)?
            .or_else(|| {
                EMPTY_SUBTREES
                    .get(index.depth() as usize)
                    .copied()
                    .map(Word::from)
            })
            .unwrap_or_default();
        Ok(node)
    }

    /// Builds a path from the node to the root.
    pub fn get_leaf_path<K>(&self, key: K) -> Result<MerklePath, StorageError>
    where
        CanonicalWord: From<K>,
    {
        self.get_leaf_index(key)
            .and_then(|node| self.get_node_path(node))
    }

    /// Builds a path from the node to the root.
    pub fn get_node_path(&self, mut index: NodeIndex) -> Result<MerklePath, StorageError> {
        let mut path = Vec::with_capacity(index.depth() as usize);
        while index.depth() > 0 {
            let sibling = self.get_node(&index.sibling())?;
            path.push(sibling);
            index.backtrack();
        }
        Ok(MerklePath::new(path))
    }

    /// Returns the index of the leaf with the specified key.
    ///
    /// If the leaf is not in the tree, returns the index at which it could have been located.
    /// Specifically, this could result in indexes of the following:
    /// - An empty node.
    /// - Another leaf which shares a prefix with the specified key.
    pub fn get_leaf_index<K>(&self, key: K) -> Result<NodeIndex, StorageError>
    where
        CanonicalWord: From<K>,
    {
        let key = CanonicalWord::from(key);
        let mut leaf = LeafIndex::from(key);
        let mut node = leaf.traverse_to_first_tier();
        self.traverse_until_empty_or_leaf(&mut leaf, &mut node)?;
        Ok(node)
    }

    /// Fetch a list of leaves given a bottom tier index.
    pub fn get_bottom_leaves(&self, index: u64) -> Result<Vec<Leaf>, StorageError> {
        self.storage
            .get_ordered_leaves(index)?
            .unwrap_or_default()
            .into_iter()
            .map(|k| {
                self.storage.get_leaf_value(&k).map(|v| match v {
                    Some(value) => Leaf::new(k, value),
                    None => unreachable!(
                        "a leaf key exists in the storage, but a corresponding value doesn't"
                    ),
                })
            })
            .collect()
    }

    /// Computes a leaf proof for the provided key.
    ///
    /// The proof can be used to verify membership and non-membership of the key.
    ///
    /// Note: this function will not assert the validity of the proof as it can verify either
    /// membership or non-membership.
    pub fn get_leaf_proof<K>(&self, key: K) -> Result<LeafProof, StorageError>
    where
        CanonicalWord: From<K>,
    {
        let key = CanonicalWord::from(key);
        let mut leaf = LeafIndex::from(key);
        let mut node = leaf.traverse_to_first_tier();
        let current = self.traverse_until_empty_or_leaf(&mut leaf, &mut node)?;

        // compute the node input, depending on the traversed node and depth.
        let input = match current {
            NodeType::Empty | NodeType::Internal => LeafProofInput::Empty,
            NodeType::Leaf if node.is_max_depth() => self
                .get_bottom_leaves(node.index())
                .map(LeafProofInput::Lower)?,
            NodeType::Leaf => {
                let key = match self.storage.get_leaf_key(&node)? {
                    Some(key) => key,
                    None => unreachable!("a node type leaf will always yield a key"),
                };
                let leaf = match self.storage.get_leaf_value(&key)? {
                    Some(value) => Leaf::new(key, value),
                    None => unreachable!("a key mapping will always yield a value"),
                };
                LeafProofInput::Upper(leaf)
            }
        };
        let path = self.get_node_path(node)?;
        Ok(LeafProof::new(input, path))
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Replaces key on the tree, overriding a previous value.
    ///
    /// Returns the new root state.
    pub fn insert<K>(&mut self, key: K, value: Word) -> Result<&Word, StorageError>
    where
        CanonicalWord: From<K>,
    {
        let key = CanonicalWord::from(key);
        let leaf = Leaf::new(key, value);

        // traverse until non-internal node
        let mut index = LeafIndex::from(&leaf);
        let mut node = index.traverse_to_first_tier();
        let current = self.traverse_until_empty_or_leaf(&mut index, &mut node)?;

        match current {
            NodeType::Internal => unreachable!("the helper function cannot yield internal node"),
            NodeType::Empty | NodeType::Leaf if node.is_max_depth() => {
                self.append_bottom_leaf((&index).into(), leaf)?
            }
            NodeType::Empty => self.replace_upper_leaf(index.into(), leaf)?,
            NodeType::Leaf => {
                // fetch the sibling leaf from the storage.
                let sibling_key = match self.storage.get_leaf_key(&node)? {
                    Some(key) => key,
                    None => unreachable!("yielded leaf type will always contain a leaf key"),
                };
                let sibling_value = match self.storage.get_leaf_value(&sibling_key)? {
                    Some(value) => value,
                    None => unreachable!("yielded leaf type will always contain a leaf value"),
                };
                let sibling = Leaf::new(sibling_key, sibling_value);

                // traverse to the same depth.
                let mut sibling_index = LeafIndex::from(&sibling);
                sibling_index.traverse_to(index.depth());
                debug_assert_eq!(NodeIndex::from(&index), NodeIndex::from(&sibling_index));

                // traverse until divergence or lowest level.
                while sibling_index.index() == index.index() && !sibling_index.is_max_depth() {
                    sibling_index.traverse();
                    index.traverse();
                }

                if sibling_index.is_max_depth() {
                    self.append_bottom_leaf(sibling_index.into(), sibling)?;
                    self.append_bottom_leaf(index.into(), leaf)?;
                } else {
                    self.replace_upper_leaf(sibling_index.into(), sibling)?;
                    self.storage.take_leaf_key(&node)?;
                    self.replace_upper_leaf(index.into(), leaf)?;
                }
            }
        }

        Ok(self.root())
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Traverse both indexes until an empty or leaf node is found.
    ///
    /// The tree definition will not allow a bottom tier to contain an internal node, so this
    /// function will always yield either leaf or empty types.
    fn traverse_until_empty_or_leaf(
        &self,
        leaf: &mut LeafIndex,
        node: &mut NodeIndex,
    ) -> Result<NodeType, StorageError> {
        let mut current = self.get_type(node)?;
        while current.is_internal() {
            *node = match leaf.next() {
                Some(node) => node,
                None => unreachable!("a path always ends with either empty or leaf"),
            };
            current = self.get_type(node)?;
        }
        Ok(current)
    }

    /// Fetch the type of a node, returning `NodeType::Empty` if absent.
    fn get_type(&self, index: &NodeIndex) -> Result<NodeType, StorageError> {
        self.storage.get_type(index).map(Option::unwrap_or_default)
    }

    /// Computes the node value of a bottom level tier provided the keys.
    ///
    /// Assumes the key value have already been inserted to the storage.
    fn replace_ordered_leaves(
        &mut self,
        index: NodeIndex,
        ordered_leaves: Vec<CanonicalWord>,
    ) -> Result<(), StorageError> {
        let node = ordered_leaves
            .iter()
            .copied()
            .map(|key| {
                self.storage.get_leaf_value(&key).map(|value| match value {
                    Some(value) => Leaf::new(key, value),
                    None => {
                        unreachable!(
                            "the leaf exists in the set, so the value must have been inserted"
                        )
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self::hash_ordered_leaves)?;

        // update the storage
        self.storage.replace_type(index, NodeType::Leaf)?;
        self.storage.replace_node(index, node.into())?;
        self.storage
            .replace_ordered_leaves(index.index(), ordered_leaves)?;
        self.update_path_to_root(index)?;
        Ok(())
    }

    /// Hash a list of ordered leaves, producing a resulting digest.
    fn hash_ordered_leaves<I, L>(leaves: I) -> RpoDigest
    where
        L: Borrow<Leaf>,
        I: IntoIterator<Item = L>,
    {
        let inputs = leaves
            .into_iter()
            .map(|leaf| (Word::from(leaf.borrow().key), leaf.borrow().value))
            .flat_map(|(key, value)| key.into_iter().chain(value.into_iter()))
            .collect::<Vec<Felt>>();
        // TODO need a hash elements in domain so we can hash the batch of leaves.
        Rpo256::hash_elements(&inputs)
    }

    /// Replace a leaf in a upper level.
    fn replace_upper_leaf(&mut self, index: NodeIndex, leaf: Leaf) -> Result<(), StorageError> {
        debug_assert_ne!(index.depth(), Self::MAX_DEPTH);
        let node = leaf.hash(index.depth());
        self.storage.replace_type(index, NodeType::Leaf)?;
        self.storage.replace_node(index, node.into())?;
        self.storage.replace_key(leaf.key, index)?;
        self.storage.replace_leaf_key(index, leaf.key)?;
        self.storage.replace_leaf_value(leaf.key, leaf.value)?;
        self.update_path_to_root(index)?;
        Ok(())
    }

    /// Replace a leaf in the bottom level.
    fn append_bottom_leaf(&mut self, index: NodeIndex, leaf: Leaf) -> Result<(), StorageError> {
        debug_assert_eq!(index.depth(), Self::MAX_DEPTH);
        self.storage.replace_key(leaf.key, index)?;
        self.storage.replace_leaf_value(leaf.key, leaf.value)?;

        // fetch the set of leaves for the bottom tier, append the leaf, and sort it.
        let mut ordered_leaves = self
            .storage
            .get_ordered_leaves(index.index())?
            .unwrap_or_default();
        ordered_leaves.push(leaf.key);
        ordered_leaves.sort();
        ordered_leaves.dedup();
        self.replace_ordered_leaves(index, ordered_leaves)
    }

    /// Update the path to the root of the tree (non-inclusive; will update from the previous depth
    /// of the given index).
    fn update_path_to_root(&mut self, mut index: NodeIndex) -> Result<(), StorageError> {
        debug_assert_ne!(index.depth(), 0);
        while index.depth() > 1 {
            let node = self.get_node(&index)?;
            let sibling = self.get_node(&index.sibling())?;
            let input = index.build_node(node, sibling);
            let node = Rpo256::merge(&input).into();
            index.backtrack();
            self.storage.replace_type(index, NodeType::Internal)?;
            self.storage.replace_node(index, node)?;
        }
        self.update_root()
    }

    /// Update the root value.
    fn update_root(&mut self) -> Result<(), StorageError> {
        let left = self.get_node(&NodeIndex::new(1, 0))?.into();
        let right = self.get_node(&NodeIndex::new(1, 1))?.into();
        self.root = Rpo256::merge(&[left, right]).into();
        self.storage.replace_node(NodeIndex::root(), self.root)?;
        Ok(())
    }
}

// NODE TYPE
// ================================================================================================

/// A definition for the allowed node types for the tiered sparse Merkle tree.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NodeType {
    Empty,
    Internal,
    Leaf,
}

impl NodeType {
    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Returns `true` if the node type is empty.
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Returns `true` if the node type is internal.
    pub const fn is_internal(&self) -> bool {
        matches!(self, Self::Internal)
    }

    /// Returns `true` if the node type is leaf.
    pub const fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf)
    }
}

impl Default for NodeType {
    fn default() -> Self {
        Self::Empty
    }
}
