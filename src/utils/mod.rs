use super::{utils::string::String, Word};
use core::fmt::{self, Write};

#[cfg(not(feature = "std"))]
pub use alloc::format;

#[cfg(feature = "std")]
pub use std::format;

mod kv_map;

// RE-EXPORTS
// ================================================================================================
pub use winter_utils::{
    string, uninit_vector, Box, ByteReader, ByteWriter, Deserializable, DeserializationError,
    Serializable, SliceReader,
};

pub mod collections {
    pub use super::kv_map::*;
    pub use winter_utils::collections::*;
}

// UTILITY FUNCTIONS
// ================================================================================================

/// Converts a [Word] into hex.
pub fn word_to_hex(w: &Word) -> Result<String, fmt::Error> {
    let mut s = String::new();

    for byte in w.iter().flat_map(|e| e.to_bytes()) {
        write!(s, "{byte:02x}")?;
    }

    Ok(s)
}
