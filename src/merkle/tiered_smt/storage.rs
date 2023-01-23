use super::{BTreeMap, CanonicalWord, Leaf, MerkleError, NodeIndex, NodeType, Vec, Word};

// TIERED SPARSE MERKLE TREE STORAGE
// ================================================================================================

// TODO we have a couple of tech-debts for the sake of simplicity of the initial implementation.
//
// - error type
// we are using `MerkleError` to avoid creating a new error variant. however, `MerkleError` is
// reserved for merkle tree logical errors, and probably shouldn't be mixed with storage errors.

/// A storage implementation for the tiered sparse merkle tree.
#[derive(Debug, Default)]
pub struct Storage {
    types: BTreeMap<NodeIndex, NodeType>,
    nodes: BTreeMap<NodeIndex, Word>,
    keys: BTreeMap<CanonicalWord, NodeIndex>,
    upper_leaf_keys: BTreeMap<NodeIndex, CanonicalWord>,
    leaf_values: BTreeMap<CanonicalWord, Word>,
    ordered_leaves: BTreeMap<u64, Vec<Leaf>>,
}

impl Storage {
    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Returns the type of a node.
    pub fn get_type(&self, index: &NodeIndex) -> Result<Option<NodeType>, MerkleError> {
        Ok(self.types.get(index).copied())
    }

    /// Returns the value of a node.
    pub fn get_node(&self, index: &NodeIndex) -> Result<Option<Word>, MerkleError> {
        Ok(self.nodes.get(index).copied())
    }

    /// Returns the index of a leaf key.
    pub fn get_leaf_index(&self, key: &CanonicalWord) -> Result<Option<NodeIndex>, MerkleError> {
        Ok(self.keys.get(key).copied())
    }

    /// Returns the leaf key of an index.
    pub fn get_leaf_key(&self, index: &NodeIndex) -> Result<Option<CanonicalWord>, MerkleError> {
        Ok(self.upper_leaf_keys.get(index).copied())
    }

    /// Returns the leaf value of its key.
    pub fn get_leaf_value(&self, key: &CanonicalWord) -> Result<Option<Word>, MerkleError> {
        Ok(self.leaf_values.get(key).copied())
    }

    /// Returns a list of leaves for a given index of the lowest depth of the tree.
    pub fn get_ordered_leaves(&self, index: u64) -> Result<Option<Vec<Leaf>>, MerkleError> {
        Ok(self.ordered_leaves.get(&index).cloned())
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Overwrites the node type of a given index.
    pub fn replace_type(&mut self, index: NodeIndex, r#type: NodeType) -> Result<(), MerkleError> {
        self.types.insert(index, r#type);
        Ok(())
    }

    /// Overwrites the node value of a given index.
    pub fn replace_node(&mut self, index: NodeIndex, node: Word) -> Result<(), MerkleError> {
        self.nodes.insert(index, node);
        Ok(())
    }

    /// Overwrites the index of a given leaf key.
    pub fn replace_key(&mut self, key: CanonicalWord, index: NodeIndex) -> Result<(), MerkleError> {
        self.keys.insert(key, index);
        Ok(())
    }

    /// Overwrites the leaf key of a given index.
    pub fn replace_leaf_key(
        &mut self,
        index: NodeIndex,
        key: CanonicalWord,
    ) -> Result<(), MerkleError> {
        self.upper_leaf_keys.insert(index, key);
        Ok(())
    }

    /// Overwrites the leaf value given its key.
    pub fn replace_leaf_value(
        &mut self,
        key: CanonicalWord,
        value: Word,
    ) -> Result<(), MerkleError> {
        self.leaf_values.insert(key, value);
        Ok(())
    }

    /// Overwrites the list of ordered leaves of the given index.
    ///
    /// Note: This will remove any previous instance, they will not be merged.
    pub fn replace_ordered_leaves(
        &mut self,
        index: u64,
        leaves: Vec<Leaf>,
    ) -> Result<(), MerkleError> {
        self.ordered_leaves.insert(index, leaves);
        Ok(())
    }

    /// Removes a type from a given index, returning it.
    pub fn take_type(&mut self, index: &NodeIndex) -> Result<Option<NodeType>, MerkleError> {
        Ok(self.types.remove(index))
    }

    /// Removes a node value from a given index, returning it.
    pub fn take_node(&mut self, index: &NodeIndex) -> Result<Option<Word>, MerkleError> {
        Ok(self.nodes.remove(index))
    }

    /// Removes a leaf key mapping index, returning it.
    pub fn take_key(&mut self, key: &CanonicalWord) -> Result<Option<NodeIndex>, MerkleError> {
        Ok(self.keys.remove(key))
    }

    /// Removes a leaf key from a given index, returning it.
    pub fn take_leaf_key(
        &mut self,
        index: &NodeIndex,
    ) -> Result<Option<CanonicalWord>, MerkleError> {
        Ok(self.upper_leaf_keys.remove(index))
    }

    /// Removes a leaf value mapping, returning it.
    pub fn take_leaf_value(&mut self, key: &CanonicalWord) -> Result<Option<Word>, MerkleError> {
        Ok(self.leaf_values.remove(key))
    }

    /// Removes an ordered leaves list for the given bottom index, returning it.
    pub fn take_ordered_leaves(&mut self, index: u64) -> Result<Option<Vec<Leaf>>, MerkleError> {
        Ok(self.ordered_leaves.remove(&index))
    }
}
