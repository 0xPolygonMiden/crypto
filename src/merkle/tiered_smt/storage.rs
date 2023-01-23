use super::{BTreeMap, Content, ContentType, RpoDigest, TreeIndex, Vec};
use core::{cell::RefCell, fmt};

#[derive(Debug, Default)]
pub struct Storage {
    payload: RefCell<BTreeMap<RpoDigest, Vec<u8>>>,
    nodes: RefCell<BTreeMap<TreeIndex, Content>>,
}

impl Storage {
    pub fn insert_payload(&self, key: RpoDigest, payload: Vec<u8>) -> Result<(), StorageError> {
        self.payload
            .try_borrow_mut()
            .map_err(|_| StorageError::PoisonedInternalWrapper)?
            .insert(key, payload);
        Ok(())
    }

    pub fn insert_node(&self, index: TreeIndex, content: Content) -> Result<(), StorageError> {
        self.nodes
            .try_borrow_mut()
            .map_err(|_| StorageError::PoisonedInternalWrapper)?
            .insert(index, content);
        Ok(())
    }

    pub fn insert_node_batch<I>(&self, args: I) -> Result<(), StorageError>
    where
        I: IntoIterator<Item = (TreeIndex, Content)>,
    {
        self.nodes
            .try_borrow_mut()
            .map_err(|_| StorageError::PoisonedInternalWrapper)?
            .extend(args);
        Ok(())
    }

    pub fn peek_node_type(&self, index: &TreeIndex) -> Result<Option<ContentType>, StorageError> {
        self.nodes
            .try_borrow()
            .map_err(|_| StorageError::PoisonedInternalWrapper)
            .map(|nodes| nodes.get(index).map(Content::r#type))
    }

    pub fn get_node_digest(&self, index: &TreeIndex) -> Result<Option<RpoDigest>, StorageError> {
        self.nodes
            .try_borrow()
            .map_err(|_| StorageError::PoisonedInternalWrapper)
            .map(|nodes| nodes.get(index).map(Content::digest).copied())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageError {
    InvalidTreeIndex,
    LeafNodeWithoutDigest,
    PoisonedInternalWrapper,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use StorageError::*;
        match self {
            InvalidTreeIndex => write!(f, "an invalid tree index was provided. the queried depth is greater than the constant maximum."),
            LeafNodeWithoutDigest => write!(f, "an indexed node is of type `leaf` in the storage, but has no associated digest. this is a storage bug!"),
            PoisonedInternalWrapper => write!(f, "an attempt to access a locked internal wrapper was made."),
        }
    }
}
