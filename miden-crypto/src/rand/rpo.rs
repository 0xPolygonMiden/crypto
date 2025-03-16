use alloc::{string::ToString, vec::Vec};

use rand_core::impls;

use super::{Felt, FeltRng, FieldElement, RandomCoin, RandomCoinError, RngCore, Word, ZERO};
use crate::{
    hash::rpo::{Rpo256, RpoDigest},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// CONSTANTS
// ================================================================================================

const STATE_WIDTH: usize = Rpo256::STATE_WIDTH;
const RATE_START: usize = Rpo256::RATE_RANGE.start;
const RATE_END: usize = Rpo256::RATE_RANGE.end;
const HALF_RATE_WIDTH: usize = (Rpo256::RATE_RANGE.end - Rpo256::RATE_RANGE.start) / 2;

// RPO RANDOM COIN
// ================================================================================================
/// A simplified version of the `SPONGE_PRG` reseedable pseudo-random number generator algorithm
/// described in <https://eprint.iacr.org/2011/499.pdf>.
///
/// The simplification is related to the following facts:
/// 1. A call to the reseed method implies one and only one call to the permutation function. This
///    is possible because in our case we never reseed with more than 4 field elements.
/// 2. As a result of the previous point, we don't make use of an input buffer to accumulate seed
///    material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpoRandomCoin {
    state: [Felt; STATE_WIDTH],
    current: usize,
}

impl RpoRandomCoin {
    /// Returns a new [RpoRandomCoin] initialize with the specified seed.
    pub fn new(seed: Word) -> Self {
        let mut state = [ZERO; STATE_WIDTH];

        for i in 0..HALF_RATE_WIDTH {
            state[RATE_START + i] += seed[i];
        }

        // Absorb
        Rpo256::apply_permutation(&mut state);

        RpoRandomCoin { state, current: RATE_START }
    }

    /// Returns an [RpoRandomCoin] instantiated from the provided components.
    ///
    /// # Panics
    /// Panics if `current` is smaller than 4 or greater than or equal to 12.
    pub fn from_parts(state: [Felt; STATE_WIDTH], current: usize) -> Self {
        assert!(
            (RATE_START..RATE_END).contains(&current),
            "current value outside of valid range"
        );
        Self { state, current }
    }

    /// Returns components of this random coin.
    pub fn into_parts(self) -> ([Felt; STATE_WIDTH], usize) {
        (self.state, self.current)
    }

    /// Fills `dest` with random data.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        <Self as RngCore>::fill_bytes(self, dest)
    }

    fn draw_basefield(&mut self) -> Felt {
        if self.current == RATE_END {
            Rpo256::apply_permutation(&mut self.state);
            self.current = RATE_START;
        }

        self.current += 1;
        self.state[self.current - 1]
    }
}

// RANDOM COIN IMPLEMENTATION
// ------------------------------------------------------------------------------------------------

impl RandomCoin for RpoRandomCoin {
    type BaseField = Felt;
    type Hasher = Rpo256;

    fn new(seed: &[Self::BaseField]) -> Self {
        let digest: Word = Rpo256::hash_elements(seed).into();
        Self::new(digest)
    }

    fn reseed(&mut self, data: RpoDigest) {
        // Reset buffer
        self.current = RATE_START;

        // Add the new seed material to the first half of the rate portion of the RPO state
        let data: Word = data.into();

        self.state[RATE_START] += data[0];
        self.state[RATE_START + 1] += data[1];
        self.state[RATE_START + 2] += data[2];
        self.state[RATE_START + 3] += data[3];

        // Absorb
        Rpo256::apply_permutation(&mut self.state);
    }

    fn check_leading_zeros(&self, value: u64) -> u32 {
        let value = Felt::new(value);
        let mut state_tmp = self.state;

        state_tmp[RATE_START] += value;

        Rpo256::apply_permutation(&mut state_tmp);

        let first_rate_element = state_tmp[RATE_START].as_int();
        first_rate_element.trailing_zeros()
    }

    fn draw<E: FieldElement<BaseField = Felt>>(&mut self) -> Result<E, RandomCoinError> {
        let ext_degree = E::EXTENSION_DEGREE;
        let mut result = vec![ZERO; ext_degree];
        for r in result.iter_mut().take(ext_degree) {
            *r = self.draw_basefield();
        }

        let result = E::slice_from_base_elements(&result);
        Ok(result[0])
    }

    fn draw_integers(
        &mut self,
        num_values: usize,
        domain_size: usize,
        nonce: u64,
    ) -> Result<Vec<usize>, RandomCoinError> {
        assert!(domain_size.is_power_of_two(), "domain size must be a power of two");
        assert!(num_values < domain_size, "number of values must be smaller than domain size");

        // absorb the nonce
        let nonce = Felt::new(nonce);
        self.state[RATE_START] += nonce;
        Rpo256::apply_permutation(&mut self.state);

        // reset the buffer and move the next random element pointer to the second rate element.
        // this is done as the first rate element will be "biased" via the provided `nonce` to
        // contain some number of leading zeros.
        self.current = RATE_START + 1;

        // determine how many bits are needed to represent valid values in the domain
        let v_mask = (domain_size - 1) as u64;

        // draw values from PRNG until we get as many unique values as specified by num_queries
        let mut values = Vec::new();
        for _ in 0..1000 {
            // get the next pseudo-random field element
            let value = self.draw_basefield().as_int();

            // use the mask to get a value within the range
            let value = (value & v_mask) as usize;

            values.push(value);
            if values.len() == num_values {
                break;
            }
        }

        if values.len() < num_values {
            return Err(RandomCoinError::FailedToDrawIntegers(num_values, values.len(), 1000));
        }

        Ok(values)
    }
}

// FELT RNG IMPLEMENTATION
// ------------------------------------------------------------------------------------------------

impl FeltRng for RpoRandomCoin {
    fn draw_element(&mut self) -> Felt {
        self.draw_basefield()
    }

    fn draw_word(&mut self) -> Word {
        let mut output = [ZERO; 4];
        for o in output.iter_mut() {
            *o = self.draw_basefield();
        }
        output
    }
}

// RNGCORE IMPLEMENTATION
// ------------------------------------------------------------------------------------------------

impl RngCore for RpoRandomCoin {
    fn next_u32(&mut self) -> u32 {
        self.draw_basefield().as_int() as u32
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }
}

// SERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for RpoRandomCoin {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.state.iter().for_each(|v| v.write_into(target));
        // casting to u8 is OK because `current` is always between 4 and 12.
        target.write_u8(self.current as u8);
    }
}

impl Deserializable for RpoRandomCoin {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let state = [
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
        ];
        let current = source.read_u8()? as usize;
        if !(RATE_START..RATE_END).contains(&current) {
            return Err(DeserializationError::InvalidValue(
                "current value outside of valid range".to_string(),
            ));
        }
        Ok(Self { state, current })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{Deserializable, FeltRng, RpoRandomCoin, Serializable, ZERO};
    use crate::ONE;

    #[test]
    fn test_feltrng_felt() {
        let mut rpocoin = RpoRandomCoin::new([ZERO; 4]);
        let output = rpocoin.draw_element();

        let mut rpocoin = RpoRandomCoin::new([ZERO; 4]);
        let expected = rpocoin.draw_basefield();

        assert_eq!(output, expected);
    }

    #[test]
    fn test_feltrng_word() {
        let mut rpocoin = RpoRandomCoin::new([ZERO; 4]);
        let output = rpocoin.draw_word();

        let mut rpocoin = RpoRandomCoin::new([ZERO; 4]);
        let mut expected = [ZERO; 4];
        for o in expected.iter_mut() {
            *o = rpocoin.draw_basefield();
        }

        assert_eq!(output, expected);
    }

    #[test]
    fn test_feltrng_serialization() {
        let coin1 = RpoRandomCoin::from_parts([ONE; 12], 5);

        let bytes = coin1.to_bytes();
        let coin2 = RpoRandomCoin::read_from_bytes(&bytes).unwrap();
        assert_eq!(coin1, coin2);
    }
}
