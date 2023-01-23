use super::{BTreeMap, Felt, Rpo256, RpoDigest, Serializable, Vec, Word};

mod bits;
pub use bits::BitsIterator;

mod content;
pub use content::{Content, ContentType};

mod index;
pub use index::TreeIndex;

mod storage;
pub use storage::{Storage, StorageError};

#[cfg(test)]
mod tests;

// TIERED SPARSE MERKLE TREE
// ================================================================================================

pub struct TieredSmt {
    // TODO this should be a constant
    empty_subtrees: Vec<RpoDigest>,
    storage: Storage,
}

impl TieredSmt {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    pub const MAX_DEPTH: usize = 64;
    pub const TIER_DEPTH: usize = 4;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    pub fn with_storage(storage: Storage) -> Self {
        // Construct empty node digests for each layer of the tree
        let empty_subtrees = (0..Self::MAX_DEPTH + 1)
            .scan(Word::default().into(), |state, _| {
                let value = *state;
                *state = Rpo256::merge(&[value, value]);
                Some(value)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        Self {
            empty_subtrees,
            storage,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn peek_node_type(&self, index: &TreeIndex) -> Result<ContentType, StorageError> {
        self.storage
            .peek_node_type(index)
            .map(Option::unwrap_or_default)
    }

    pub fn get_node_digest(&self, index: &TreeIndex) -> Result<RpoDigest, StorageError> {
        self.storage
            .get_node_digest(index)?
            .or_else(|| self.empty_subtrees.get(index.depth() as usize).copied())
            .ok_or(StorageError::InvalidTreeIndex)
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    pub fn insert<T>(&self, value: &T) -> Result<RpoDigest, StorageError>
    where
        T: Serializable,
    {
        let payload = value.to_bytes();
        let key = Rpo256::hash(&payload);
        self.insert_key(key)?;
        self.storage.insert_payload(key, payload)?;
        Ok(key)
    }

    /// Insert a value into the tree, overriding the key with the provided value.
    ///
    /// Note: this might lead to an inconsistent state of the tree if the key is not computed
    /// correctly.
    #[cfg(any(test, feature = "internals"))]
    pub fn insert_with_key<T>(&self, key: RpoDigest, value: &T) -> Result<RpoDigest, StorageError>
    where
        T: Serializable,
    {
        let payload = value.to_bytes();
        self.insert_key(key)?;
        self.storage.insert_payload(key, payload)?;
        Ok(key)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Traverse from index.depth-1 to depth (inclusive), generating an internal node for each
    /// iteration.
    fn update_to_depth(
        &self,
        mut value: RpoDigest,
        mut index: TreeIndex,
        depth: u32,
        batch: &mut BTreeMap<TreeIndex, Content>,
    ) -> Result<(), StorageError> {
        for _ in depth..index.depth() {
            // fetch sibling digest, first checking if it will be updated with this batch
            let sibling = index.sibling();
            let sibling = batch
                .get(&sibling)
                .map(|c| Ok(*c.digest()))
                .unwrap_or_else(|| self.get_node_digest(&sibling))?;

            // compute merged value
            value = Rpo256::merge(&index.build_node(value, sibling));
            index = index.reverse();

            // push result to batch as internal node
            batch.insert(index, Content::internal(value));
        }
        Ok(())
    }

    fn insert_key(&self, key: RpoDigest) -> Result<(), StorageError> {
        // use a batch to cache this update instead of locking the storage for multiple ticks
        let mut batch = BTreeMap::new();

        // iterate the key bits
        // TODO should be hash in domain
        let mut bits = BitsIterator::from(&key).take(Self::MAX_DEPTH);
        let mut index = BitsIterator::traverse_from_root(bits.by_ref());

        // if root is empty, create an initial sub-tree with a single leaf
        if self.peek_node_type(&TreeIndex::root())?.is_empty() {
            batch.insert(index, Content::leaf(key));
            self.update_to_depth(key, index, 0, &mut batch)?;
            self.storage.insert_node_batch(batch)?;
            return Ok(());
        }

        // traverse until non-internal node
        let mut current = self.peek_node_type(&index)?;
        while current.is_internal() {
            index = match BitsIterator::traverse(index, bits.by_ref()) {
                Some(idx) => idx,
                None => unimplemented!("handle ordered list"),
            };
            current = self.peek_node_type(&index)?;
        }

        // if empty node, then replace with leaf. create a sub-tree otherwise
        if current.is_empty() {
            batch.insert(index, Content::leaf(key));
        } else if current.is_leaf() {
            // a node that is declared as leaf by the storage should have a digest
            let sibling_digest = self
                .storage
                .get_node_digest(&index)?
                .ok_or(StorageError::LeafNodeWithoutDigest)?;

            // iterate the bits of the sibling key to compute its index in the new sub-tree
            let mut sibling_bits = BitsIterator::from(&sibling_digest)
                .take(Self::MAX_DEPTH)
                .skip(index.depth() as usize);

            // traverse until the indexes diverge
            let mut sibling_index = index;
            while sibling_index == index {
                sibling_index = match BitsIterator::traverse(sibling_index, sibling_bits.by_ref()) {
                    Some(idx) => idx,
                    None => unimplemented!("handle ordered list"),
                };

                index = match BitsIterator::traverse(index, bits.by_ref()) {
                    Some(idx) => idx,
                    None => unimplemented!("handle ordered list"),
                };
            }

            // append the leaves with the found indexes
            batch.insert(sibling_index, Content::leaf(sibling_digest));
            batch.insert(index, Content::leaf(key));

            // update from sibling leaf to level prior to sub-tree root
            let mut sibling_path = sibling_index;
            let mut path = index;
            while sibling_path != path {
                sibling_path = sibling_path.reverse();
                path = path.reverse();
            }
            self.update_to_depth(
                sibling_digest,
                sibling_index,
                (sibling_path.depth() + 1).min(sibling_path.depth()),
                &mut batch,
            )?;

            // update from leaf to root
            self.update_to_depth(key, index, 0, &mut batch)?;
        }

        self.storage.insert_node_batch(batch)
    }
}
