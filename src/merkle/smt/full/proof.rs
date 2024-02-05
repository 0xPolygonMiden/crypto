use super::{MerklePath, RpoDigest, SmtLeaf, SmtProofError, Word, SMT_DEPTH};

/// A proof which can be used to assert membership (or non-membership) of key-value pairs in a
/// [`super::Smt`].
///
/// The proof consists of a Merkle path and leaf which describes the node located at the base of the
/// path.
#[derive(PartialEq, Eq, Debug)]
pub struct SmtProof {
    path: MerklePath,
    leaf: SmtLeaf,
}

impl SmtProof {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a new instance of [`SmtProof`] instantiated from the specified path and leaf.
    ///
    /// # Errors
    /// Returns an error if the path length is not [`SMT_DEPTH`].
    pub fn new(path: MerklePath, leaf: SmtLeaf) -> Result<Self, SmtProofError> {
        if path.len() != SMT_DEPTH.into() {
            return Err(SmtProofError::InvalidPathLength(path.len()));
        }

        Ok(Self { path, leaf })
    }

    /// Returns a new instance of [`SmtProof`] instantiated from the specified path and leaf.
    ///
    /// The length of the path is not checked. Reserved for internal use.
    pub(crate) fn new_unchecked(path: MerklePath, leaf: SmtLeaf) -> Self {
        Self { path, leaf }
    }

    // PROOF VERIFIER
    // --------------------------------------------------------------------------------------------

    /// Returns true if a [`super::Smt`] with the specified root contains the provided
    /// key-value pair.
    ///
    /// Note: this method cannot be used to assert non-membership. That is, if false is returned,
    /// it does not mean that the provided key-value pair is not in the tree.
    pub fn verify_membership(&self, key: &RpoDigest, value: &Word, root: &RpoDigest) -> bool {
        let maybe_value_in_leaf = self.leaf.get_value(key);

        match maybe_value_in_leaf {
            Some(value_in_leaf) => {
                // The value must match for the proof to be valid
                if value_in_leaf != *value {
                    return false;
                }

                // make sure the Merkle path resolves to the correct root
                self.compute_root() == *root
            }
            // If the key maps to a different leaf, the proof cannot verify membership of `value`
            None => false,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the value associated with the specific key according to this proof, or None if
    /// this proof does not contain a value for the specified key.
    ///
    /// A key-value pair generated by using this method should pass the `verify_membership()` check.
    pub fn get(&self, key: &RpoDigest) -> Option<Word> {
        self.leaf.get_value(key)
    }

    /// Computes the root of a [`super::Smt`] to which this proof resolves.
    pub fn compute_root(&self) -> RpoDigest {
        self.path
            .compute_root(self.leaf.index().value(), self.leaf.hash())
            .expect("failed to compute Merkle path root")
    }

    /// Consume the proof and returns its parts.
    pub fn into_parts(self) -> (MerklePath, SmtLeaf) {
        (self.path, self.leaf)
    }
}
