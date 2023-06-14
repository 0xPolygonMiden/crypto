use super::Word;
use crate::utils::string::String;
use core::fmt::{self, Write};

#[cfg(not(feature = "std"))]
pub use alloc::format;

#[cfg(feature = "std")]
pub use std::format;

// RE-EXPORTS
// ================================================================================================
pub use winter_utils::{
    collections, string, uninit_vector, ByteReader, ByteWriter, Deserializable,
    DeserializationError, Serializable, SliceReader,
};

/// Converts a [Word] into hex.
pub fn word_to_hex(w: &Word) -> Result<String, fmt::Error> {
    let mut s = String::new();

    for byte in w.iter().flat_map(|e| e.to_bytes()) {
        write!(s, "{byte:02x}")?;
    }

    Ok(s)
}
