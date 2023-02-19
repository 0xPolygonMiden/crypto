use super::{BTreeMap, CanonicalWord, NodeIndex, SimpleSmt, TieredSmt, Word};

#[derive(Debug, Default)]
pub struct Storage {
    trees: BTreeMap<NodeIndex, SimpleSmt>,
    leaf_indexes: BTreeMap<CanonicalWord, NodeIndex>,
    leaf_values: BTreeMap<CanonicalWord, Word>,
    lowest_key_at_index: BTreeMap<NodeIndex, CanonicalWord>,
    bottom_leaves: BTreeMap<u64, BTreeMap<CanonicalWord, Word>>,
}

impl Storage {
    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Fetch a sub-tree.
    pub fn get_tree(&self, index: &NodeIndex) -> Option<&SimpleSmt> {
        self.trees.get(index)
    }

    /// Fetch a leaf index.
    pub fn get_leaf_key(&self, key: &CanonicalWord) -> Option<&NodeIndex> {
        self.leaf_indexes.get(key)
    }

    /// Fetch a leaf value.
    pub fn get_leaf_value(&self, key: &CanonicalWord) -> Option<&Word> {
        self.leaf_values.get(key)
    }

    /// Fetch a bottom leaf set.
    pub fn get_bottom_leaves(&self, index: u64) -> Option<&BTreeMap<CanonicalWord, Word>> {
        self.bottom_leaves.get(&index)
    }

    /// Fetch the lowest key at the given index.
    pub fn get_lowest_key_at_index(&self, index: &NodeIndex) -> Option<&CanonicalWord> {
        self.lowest_key_at_index.get(index)
    }

    /// Returns `true` if a tier-level node is a sub-tree root.
    pub fn is_subtree_root(&self, index: &NodeIndex) -> bool {
        self.trees.contains_key(index)
    }

    /// Returns `true` if a tier-level node is occupied by a leaf.
    pub fn is_leaf(&self, index: &NodeIndex) -> bool {
        self.lowest_key_at_index.contains_key(index)
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Replace a sub-tree.
    pub fn replace_tree(&mut self, index: NodeIndex, tree: SimpleSmt) -> bool {
        self.trees.insert(index, tree).is_some()
    }

    /// Replace a leaf key mapping for a node.
    pub fn replace_leaf_key(&mut self, key: CanonicalWord, index: NodeIndex) -> bool {
        let lowest = if index.depth() == TieredSmt::MAX_DEPTH {
            self.bottom_leaves
                .get(&index.value())
                .and_then(|leaves| leaves.keys().next())
                .copied()
                .unwrap_or(key)
                .min(key)
        } else {
            key
        };
        self.lowest_key_at_index.insert(index, lowest);
        self.leaf_indexes.insert(key, index).is_some()
    }

    /// Replace a leaf value.
    pub fn replace_leaf_value(&mut self, key: CanonicalWord, value: Word) -> bool {
        self.leaf_values.insert(key, value).is_some()
    }

    /// Replace a bottom leaf with the provided node index.
    pub fn replace_bottom_leaf(&mut self, index: u64, key: CanonicalWord, value: Word) -> bool {
        self.bottom_leaves
            .get_mut(&index)
            .and_then(|leaves| leaves.insert(key, value))
            .is_some()
    }

    /// Remove a sub-tree from the storage, returning it if found.
    pub fn take_tree(&mut self, index: &NodeIndex) -> Option<SimpleSmt> {
        self.trees.remove(index)
    }

    /// Remove a leaf key mapping to a node from the storage, returning it if found.
    pub fn take_leaf_key(&mut self, key: &CanonicalWord) -> Option<NodeIndex> {
        let index = match self.leaf_indexes.remove(key) {
            Some(i) => i,
            None => return None,
        };
        if index.depth() == TieredSmt::MAX_DEPTH {
            let lowest_key_at_bottom = self
                .bottom_leaves
                .get(&index.value())
                .and_then(|leaves| leaves.keys().find(|k| k != &key));

            match lowest_key_at_bottom {
                Some(lowest) => self.lowest_key_at_index.insert(index, *lowest),
                None => self.lowest_key_at_index.remove(&index),
            };
        } else {
            self.lowest_key_at_index.remove(&index);
        }
        Some(index)
    }

    /// Remove a leaf key mapping to a value from the storage, returning it if found.
    pub fn take_leaf_value(&mut self, index: &CanonicalWord) -> Option<Word> {
        self.leaf_values.remove(index)
    }

    /// Remove a key/value mapping from the bottom leaves, returning the value if found.
    pub fn take_bottom_leaf(&mut self, index: u64, key: &CanonicalWord) -> Option<Word> {
        self.bottom_leaves
            .get_mut(&index)
            .and_then(|leaves| leaves.remove(key))
    }

    /// Remove a set of key/value mapping from the bottom leaves, returning the value if found.
    pub fn take_bottom_leaves(&mut self, index: u64) -> Option<BTreeMap<CanonicalWord, Word>> {
        self.bottom_leaves.remove(&index)
    }
}
