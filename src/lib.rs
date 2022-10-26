pub use winter_crypto::{Digest, ElementHasher, Hasher as HashFn};
pub use winter_math::{
    fields::{f64::BaseElement as Felt, QuadExtension},
    log2, ExtensionOf, FieldElement, StarkField,
};
pub use winter_utils::{
    collections::{BTreeMap, Vec},
    uninit_vector, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    SliceReader,
};

pub mod hash;
pub mod merkle;

// TYPE ALIASES
// ================================================================================================

pub type Word = [Felt; 4];

// CONSTANTS
// ================================================================================================

/// Field element representing ZERO in the base field of the VM.
pub const ZERO: Felt = Felt::ZERO;

/// Field element representing ONE in the base field of the VM.
pub const ONE: Felt = Felt::ONE;
