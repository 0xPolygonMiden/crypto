use super::{
    BTreeMap, EmptySubtreeRoots, MerkleError, MerklePath, NodeIndex, Rpo256, RpoDigest, StarkField,
    Vec, Word, EMPTY_WORD,
};

#[cfg(test)]
mod tests;

// TIERED SPARSE MERKLE TREE
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TieredSmt {
    root: RpoDigest,
    nodes: BTreeMap<NodeIndex, RpoDigest>,
    upper_leaves: BTreeMap<NodeIndex, RpoDigest>,
    bottom_leaves: BTreeMap<u64, Vec<RpoDigest>>,
    values: BTreeMap<RpoDigest, Word>,
}

impl TieredSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    const MAX_DEPTH: u8 = 64;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    pub fn new() -> Self {
        Self {
            root: EmptySubtreeRoots::empty_hashes(Self::MAX_DEPTH)[0],
            nodes: BTreeMap::new(),
            upper_leaves: BTreeMap::new(),
            bottom_leaves: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub const fn root(&self) -> RpoDigest {
        self.root
    }

    pub fn get_node(&self, index: NodeIndex) -> Result<RpoDigest, MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > Self::MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        } else if !self.is_node_available(index) {
            todo!()
        }

        Ok(self.get_branch_node(&index))
    }

    pub fn get_path(&self, mut index: NodeIndex) -> Result<MerklePath, MerkleError> {
        if index.is_root() {
            return Err(MerkleError::DepthTooSmall(index.depth()));
        } else if index.depth() > Self::MAX_DEPTH {
            return Err(MerkleError::DepthTooBig(index.depth() as u64));
        } else if !self.is_node_available(index) {
            todo!()
        }

        let mut path = Vec::with_capacity(index.depth() as usize);
        for _ in 0..index.depth() {
            let node = self.get_branch_node(&index.sibling());
            path.push(node.into());
            index.move_up();
        }
        Ok(path.into())
    }

    pub fn get_value(&self, key: RpoDigest) -> Result<Word, MerkleError> {
        match self.values.get(&key) {
            Some(value) => Ok(*value),
            None => Ok(EMPTY_WORD),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    pub fn insert(&mut self, key: RpoDigest, value: Word) -> Result<Word, MerkleError> {
        let (mut index, leaf_key) = self.get_insert_location(&key);

        if let Some(other_key) = leaf_key {
            if other_key != key {
                let common_prefix_len = get_common_prefix_length(&key, &other_key);
                let depth = common_prefix_len + 16;

                let other_index = key_to_index(&other_key, depth);
                self.move_leaf_node(other_key, index, other_index);

                index = key_to_index(&key, depth);
            }
        }

        let old_value = self.values.insert(key, value).unwrap_or(EMPTY_WORD);
        if value != old_value {
            self.upper_leaves.insert(index, key);
            let new_node = build_leaf_node(key, value, index.depth().into());
            self.root = self.update_path(index, new_node);
        }

        Ok(old_value)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    fn is_node_available(&self, index: NodeIndex) -> bool {
        match index.depth() {
            32 => true,
            48 => true,
            _ => true,
        }
    }

    fn get_branch_node(&self, index: &NodeIndex) -> RpoDigest {
        match self.nodes.get(index) {
            Some(node) => *node,
            None => EmptySubtreeRoots::empty_hashes(Self::MAX_DEPTH)[index.depth() as usize],
        }
    }

    fn get_insert_location(&self, key: &RpoDigest) -> (NodeIndex, Option<RpoDigest>) {
        let mse = Word::from(key)[3].as_int();
        for depth in (16..64).step_by(16) {
            let index = NodeIndex::new(depth, mse >> (Self::MAX_DEPTH - depth)).unwrap();
            if let Some(leaf_key) = self.upper_leaves.get(&index) {
                return (index, Some(*leaf_key));
            } else if self.nodes.contains_key(&index) {
                continue;
            } else {
                return (index, None);
            }
        }

        // TODO: handle bottom tier
        unimplemented!()
    }

    fn move_leaf_node(&mut self, key: RpoDigest, old_index: NodeIndex, new_index: NodeIndex) {
        self.upper_leaves.remove(&old_index).unwrap();
        self.upper_leaves.insert(new_index, key);
        let value = *self.values.get(&key).unwrap();
        let new_node = build_leaf_node(key, value, new_index.depth().into());
        self.update_path(new_index, new_node);
    }

    fn update_path(&mut self, mut index: NodeIndex, mut node: RpoDigest) -> RpoDigest {
        for _ in 0..index.depth() {
            self.nodes.insert(index, node);
            let sibling = self.get_branch_node(&index.sibling());
            node = Rpo256::merge(&index.build_node(node, sibling));
            index.move_up();
        }
        node
    }
}

impl Default for TieredSmt {
    fn default() -> Self {
        Self::new()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn get_remaining_path(key: RpoDigest, depth: u32) -> RpoDigest {
    let mut key = Word::from(key);
    let remaining = (key[3].as_int() << depth) >> depth;
    key[3] = remaining.into();
    key.into()
}

fn build_leaf_node(key: RpoDigest, value: Word, depth: u32) -> RpoDigest {
    let remaining_path = get_remaining_path(key, depth);
    Rpo256::merge_in_domain(&[remaining_path, value.into()], depth.into())
}

fn get_common_prefix_length(key1: &RpoDigest, key2: &RpoDigest) -> u8 {
    let e1 = Word::from(key1)[3].as_int();
    let e2 = Word::from(key2)[3].as_int();

    if e1 == e2 {
        64
    } else if e1 >> 16 == e2 >> 16 {
        48
    } else if e1 >> 32 == e2 >> 32 {
        32
    } else if e1 >> 48 == e2 >> 48 {
        16
    } else {
        0
    }
}

fn key_to_index(key: &RpoDigest, depth: u8) -> NodeIndex {
    let mse = Word::from(key)[3].as_int();
    let value = match depth {
        16 | 32 | 48 => mse >> (depth as u32),
        _ => unreachable!("invalid depth: {depth}"),
    };

    // TODO: use unchecked version?
    NodeIndex::new(depth, value).unwrap()
}
