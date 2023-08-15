use super::{
    get_common_prefix_tier_depth, get_key_prefix, hash_bottom_leaf, hash_upper_leaf,
    EmptySubtreeRoots, LeafNodeIndex, MerklePath, RpoDigest, TieredSmtProofError, Vec, MAX_DEPTH,
    TIER_DEPTHS,
};

// TIERED SPARSE MERKLE TREE PROOF
// ================================================================================================

/// A proof which can be used to assert membership (or non-membership) of key-value pairs in a
/// Tiered Sparse Merkle tree.
///
/// The proof consists of a Merkle path and one or more key-value entries which describe the node
/// located at the base of the path. If the node at the base of the path resolves to [ZERO; 4],
/// the entries will contain a single item with value set to [ZERO; 4].
#[derive(PartialEq, Eq, Debug)]
pub struct TieredSmtProof<T> {
    path: MerklePath,
    entries: Vec<(RpoDigest, T)>,
}

impl<T> TieredSmtProof<T> {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Consume the proof and returns its parts.
    pub fn into_parts(self) -> (MerklePath, Vec<(RpoDigest, T)>) {
        (self.path, self.entries)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------
}

impl<T> TieredSmtProof<T>
where
    T: Default + PartialEq,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [TieredSmtProof] instantiated from the specified path and entries.
    ///
    /// # Panics
    /// Panics if:
    /// - The length of the path is greater than 64.
    /// - Entries is an empty vector.
    /// - Entries contains more than 1 item, but the length of the path is not 64.
    /// - Entries contains more than 1 item, and one of the items has value set to [ZERO; 4].
    /// - Entries contains multiple items with keys which don't share the same 64-bit prefix.
    pub fn new<I>(path: MerklePath, entries: I) -> Result<Self, TieredSmtProofError>
    where
        I: IntoIterator<Item = (RpoDigest, T)>,
    {
        let entries: Vec<(RpoDigest, T)> = entries.into_iter().collect();

        if !TIER_DEPTHS.into_iter().any(|e| e == path.depth()) {
            return Err(TieredSmtProofError::NotATierPath(path.depth()));
        }

        if entries.is_empty() {
            return Err(TieredSmtProofError::EntriesEmpty);
        }

        if entries.len() > 1 {
            if path.depth() != MAX_DEPTH {
                return Err(TieredSmtProofError::MultipleEntriesOutsideLastTier);
            }

            let prefix = get_key_prefix(&entries[0].0);
            for entry in entries.iter().skip(1) {
                if entry.1 == T::default() {
                    return Err(TieredSmtProofError::EmptyValueNotAllowed);
                }
                let current = get_key_prefix(&entry.0);
                if prefix != current {
                    return Err(TieredSmtProofError::MismatchedPrefixes(prefix, current));
                }
            }
        }

        Ok(Self { path, entries })
    }

    /// Returns true if the proof is for an empty value.
    fn is_value_empty(&self) -> bool {
        self.entries[0].1 == T::default()
    }
}

impl<T> TieredSmtProof<T>
where
    T: Default + PartialEq + Into<RpoDigest> + Copy,
{
    /// Returns true if a Tiered Sparse Merkle tree with the specified root contains the provided
    /// key-value pair.
    ///
    /// Note: this method cannot be used to assert non-membership. That is, if false is returned,
    /// it does not mean that the provided key-value pair is not in the tree.
    pub fn verify_membership(&self, key: &RpoDigest, value: &T, root: &RpoDigest) -> bool {
        if self.is_value_empty() {
            if value != &T::default() {
                return false;
            }
            // if the proof is for an empty value, we can verify it against any key which has a
            // common prefix with the key storied in entries, but the prefix must be greater than
            // the path length
            let common_prefix_tier = get_common_prefix_tier_depth(key, &self.entries[0].0);
            if common_prefix_tier < self.path.depth() {
                return false;
            }
        } else if !self.entries.iter().any(|(k, v)| k == key && v == value) {
            return false;
        }

        // make sure the Merkle path resolves to the correct root
        root == &self.compute_root()
    }

    /// Returns the value associated with the specific key according to this proof, or None if
    /// this proof does not contain a value for the specified key.
    ///
    /// A key-value pair generated by using this method should pass the `verify_membership()` check.
    pub fn get(&self, key: &RpoDigest) -> Option<T> {
        if self.is_value_empty() {
            let common_prefix_tier = get_common_prefix_tier_depth(key, &self.entries[0].0);
            if common_prefix_tier < self.path.depth() {
                None
            } else {
                Some(T::default())
            }
        } else {
            self.entries.iter().find(|(k, _)| k == key).map(|(_, value)| *value)
        }
    }

    /// Computes the root of a Tiered Sparse Merkle tree to which this proof resolve.
    pub fn compute_root(&self) -> RpoDigest {
        let node = self.build_node();
        let index = LeafNodeIndex::from_key(&self.entries[0].0, self.path.depth());
        self.path
            .compute_root(index.value(), node)
            .expect("failed to compute Merkle path root")
    }

    /// Converts the entries contained in this proof into a node value for node at the base of the
    /// path contained in this proof.
    fn build_node(&self) -> RpoDigest {
        let depth = self.path.depth();
        if self.is_value_empty() {
            EmptySubtreeRoots::empty_hashes(MAX_DEPTH)[depth as usize]
        } else if depth == MAX_DEPTH {
            hash_bottom_leaf(&self.entries)
        } else {
            let (key, value) = &self.entries[0];
            hash_upper_leaf(*key, value, depth)
        }
    }
}
