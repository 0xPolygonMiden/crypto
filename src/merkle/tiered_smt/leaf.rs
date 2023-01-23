use super::{CanonicalWord, Felt, LeafIndex, Rpo256, RpoDigest, Word};

// LEAF
// ================================================================================================

/// A key-value pair, representing an element of a tree.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Leaf {
    pub key: CanonicalWord,
    pub value: Word,
}

impl From<(CanonicalWord, Word)> for Leaf {
    fn from(args: (CanonicalWord, Word)) -> Self {
        Self {
            key: args.0,
            value: args.1,
        }
    }
}

impl Leaf {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new leaf instance.
    pub const fn new(key: CanonicalWord, value: Word) -> Self {
        Self { key, value }
    }

    // PROVIDERS
    // --------------------------------------------------------------------------------------------

    /// Returns the hash of the leaf for a given depth.
    ///
    /// Note: the node value of the maximum depth of a tiered tree is a compound value of an
    /// ordered list of the neighbours of the leaf in that node. It will correspond to this hash
    /// only if the leaf is the only member of that node.
    pub fn hash(&self, depth: u8) -> RpoDigest {
        let domain = Felt::new(depth as u64);
        let remaining = LeafIndex::from(self).remaining_path_with_depth(depth);
        Rpo256::merge_in_domain(&[remaining.into(), self.value.into()], domain)
    }
}
