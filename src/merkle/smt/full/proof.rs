use super::{MerklePath, RpoDigest, SmtLeaf, SmtProofError, Word, SMT_DEPTH};

/// A proof which can be used to assert membership (or non-membership) of key-value pairs in a
/// [`super::Smt`].
///
/// The proof consists of a Merkle path and leaf which describes the node located at the base of the
/// path. If the node at the base of the path resolves to [ZERO; 4], the entries will contain a
/// single item with value set to [ZERO; 4].
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

    // PROOF VERIFIER
    // --------------------------------------------------------------------------------------------

    /// Returns true if a [`super::Smt`] with the specified root contains the provided
    /// key-value pair.
    ///
    /// Note: this method cannot be used to assert non-membership. That is, if false is returned,
    /// it does not mean that the provided key-value pair is not in the tree.
    pub fn verify_membership(&self, key: &RpoDigest, value: &Word, root: &RpoDigest) -> bool {
        todo!()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the value associated with the specific key according to this proof, or None if
    /// this proof does not contain a value for the specified key.
    ///
    /// A key-value pair generated by using this method should pass the `verify_membership()` check.
    pub fn get(&self, key: &RpoDigest) -> Option<Word> {
        todo!()
    }

    /// Computes the root of a [`super::Smt`] to which this proof resolves.
    pub fn compute_root(&self) -> RpoDigest {
        todo!()
    }

    /// Consume the proof and returns its parts.
    pub fn into_parts(self) -> (MerklePath, SmtLeaf) {
        todo!()
    }
}
