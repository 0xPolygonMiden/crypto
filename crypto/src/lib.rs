pub use winterfell::math::{
    fields::{f64::BaseElement as Felt, QuadExtension},
    ExtensionOf, FieldElement, StarkField,
};

pub mod hash;
pub mod merkle;

// TYPE ALIASES
// ================================================================================================

pub type Word = [Felt; 4];
