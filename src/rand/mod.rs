//! Pseudo-random element generation.

pub use winter_crypto::{DefaultRandomCoin as WinterRandomCoin, RandomCoin, RandomCoinError};

use crate::{Felt, FieldElement, StarkField, Word, ZERO};

mod rpo;
pub use rpo::RpoRandomCoin;

/// Pseudo-random element generator.
///
/// An instance can be used to draw, uniformly at random, base field elements as well as [Word]s.
pub trait FeltRng {
    /// Draw, uniformly at random, a base field element.
    fn draw_element(&mut self) -> Felt;

    /// Draw, uniformly at random, a [Word].
    fn draw_word(&mut self) -> Word;
}
