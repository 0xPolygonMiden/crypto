use core::fmt::Display;

#[derive(Debug, PartialEq, Eq)]
pub enum TieredSmtProofError {
    EntriesEmpty,
    PathTooLong,
    NotATierPath(u8),
    MultipleEntriesOutsideLastTier,
    EmptyValueNotAllowed,
    UnmatchingPrefixes(u64, u64),
}

impl Display for TieredSmtProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TieredSmtProofError::EntriesEmpty => {
                write!(f, "Missing entries for tiered sparse merkle tree proof")
            }
            TieredSmtProofError::PathTooLong => {
                write!(
                    f,
                    "Path longer than maximum depth of 64 for tiered sparse merkle tree proof"
                )
            }
            TieredSmtProofError::NotATierPath(got) => {
                write!(
                    f,
                    "Path length does not correspond to a tier. Got {} Expected one of 16,32,48,64",
                    got
                )
            }
            TieredSmtProofError::MultipleEntriesOutsideLastTier => {
                write!(f, "Multiple entries are only allowed for the last tier (depth 64)")
            }
            TieredSmtProofError::EmptyValueNotAllowed => {
                write!(
                    f,
                    "The empty value [0,0,0,0] is not allowed inside a tiered sparse merkle tree"
                )
            }
            TieredSmtProofError::UnmatchingPrefixes(first, second) => {
                write!(f, "Not all leaves have the same prefix. First {} second {}", first, second)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TieredSmtProofError {}
