use core::fmt::Display;

#[derive(Debug, PartialEq, Eq)]
pub enum TieredSmtProofError {
    EntriesEmpty,
    EmptyValueNotAllowed,
    MismatchedPrefixes(u64, u64),
    MultipleEntriesOutsideLastTier,
    NotATierPath(u8),
    PathTooLong,
}

impl Display for TieredSmtProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TieredSmtProofError::EntriesEmpty => {
                write!(f, "Missing entries for tiered sparse merkle tree proof")
            }
            TieredSmtProofError::EmptyValueNotAllowed => {
                write!(
                    f,
                    "The empty value [0, 0, 0, 0] is not allowed inside a tiered sparse merkle tree"
                )
            }
            TieredSmtProofError::MismatchedPrefixes(first, second) => {
                write!(f, "Not all leaves have the same prefix. First {first} second {second}")
            }
            TieredSmtProofError::MultipleEntriesOutsideLastTier => {
                write!(f, "Multiple entries are only allowed for the last tier (depth 64)")
            }
            TieredSmtProofError::NotATierPath(got) => {
                write!(
                    f,
                    "Path length does not correspond to a tier. Got {got} Expected one of 16, 32, 48, 64"
                )
            }
            TieredSmtProofError::PathTooLong => {
                write!(
                    f,
                    "Path longer than maximum depth of 64 for tiered sparse merkle tree proof"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TieredSmtProofError {}
