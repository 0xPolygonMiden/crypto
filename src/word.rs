use crate::{hash::rpo::RpoDigest, Felt, StarkField};
use core::ops::Deref;

// TYPE ALIASES
// ================================================================================================

/// A group of four field elements in the Miden base field.
pub type Word = [Felt; WORD_SIZE];

// CONSTANTS
// ================================================================================================

/// Number of field elements in a word.
pub const WORD_SIZE: usize = 4;

// CANONICAL WORD
// ================================================================================================

/// A `[Word]` in canonical representation.
#[derive(Copy, Clone, Debug, Default, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct CanonicalWord([u64; WORD_SIZE]);

impl AsRef<[u64; WORD_SIZE]> for CanonicalWord {
    fn as_ref(&self) -> &[u64; WORD_SIZE] {
        &self.0
    }
}

impl Deref for CanonicalWord {
    type Target = [u64; WORD_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Word> for CanonicalWord {
    fn from(value: &Word) -> Self {
        Self([
            value[0].as_int(),
            value[1].as_int(),
            value[2].as_int(),
            value[3].as_int(),
        ])
    }
}

impl From<Word> for CanonicalWord {
    fn from(value: Word) -> Self {
        Self::from(&value)
    }
}

impl From<CanonicalWord> for Word {
    fn from(value: CanonicalWord) -> Self {
        [
            Felt::from_mont(value.0[0]),
            Felt::from_mont(value.0[1]),
            Felt::from_mont(value.0[2]),
            Felt::from_mont(value.0[3]),
        ]
    }
}

impl From<&CanonicalWord> for Word {
    fn from(value: &CanonicalWord) -> Self {
        [
            Felt::from_mont(value.0[0]),
            Felt::from_mont(value.0[1]),
            Felt::from_mont(value.0[2]),
            Felt::from_mont(value.0[3]),
        ]
    }
}

impl From<CanonicalWord> for RpoDigest {
    fn from(value: CanonicalWord) -> Self {
        Word::from(value).into()
    }
}

impl CanonicalWord {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the last limb of the key.
    pub const fn last_limb(&self) -> u64 {
        self.0[3]
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Updates the limb used to compute the merkle path of a key.
    pub const fn with_path(mut self, path: u64) -> Self {
        self.0[3] = path;
        self
    }
}
