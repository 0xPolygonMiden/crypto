//! Pseudo-random element generation.

pub use winter_crypto::{RandomCoin, RandomCoinError};

use crate::{Felt, Word, ZERO};

mod rpo;

/// Pseudo-random element generator.
///
/// An instance can be used to draw, uniformly at random, basefield elements as well as `Word`s.
pub trait FeltRng {
    /// Draw, uniformly at random, a basefield element.
    fn draw_element(&mut self) -> Felt;

    /// Draw, uniformly at random, a `Word`.
    fn draw_word(&mut self) -> Word;
}
