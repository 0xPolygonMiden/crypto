use super::{
    add_constants, apply_inv_sbox, apply_mds, apply_sbox,
    optimized_add_constants_and_apply_inv_sbox, optimized_add_constants_and_apply_sbox, Digest,
    ElementHasher, Felt, FieldElement, Hasher, StarkField, ARK1, ARK2, BINARY_CHUNK_SIZE,
    CAPACITY_RANGE, DIGEST_BYTES, DIGEST_RANGE, DIGEST_SIZE, INPUT1_RANGE, INPUT2_RANGE, MDS,
    NUM_ROUNDS, ONE, RATE_RANGE, RATE_WIDTH, STATE_WIDTH, ZERO,
};
use core::{convert::TryInto, ops::Range};

mod digest;
pub use digest::RpoDigest;

#[cfg(test)]
mod tests;

// HASHER IMPLEMENTATION
// ================================================================================================

/// Implementation of the Rescue Prime Optimized hash function with 256-bit output.
///
/// The hash function is implemented according to the Rescue Prime Optimized
/// [specifications](https://eprint.iacr.org/2022/1577)
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus 2^64 - 2^32 + 1.
/// * State width: 12 field elements.
/// * Capacity size: 4 field elements.
/// * Number of founds: 7.
/// * S-Box degree: 7.
///
/// The above parameters target 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Rpo256::hash_elements), [merge()](Rpo256::merge), and
/// [merge_with_int()](Rpo256::merge_with_int) are internally consistent. That is, computing
/// a hash for the same set of elements using these functions will always produce the same
/// result. For example, merging two digests using [merge()](Rpo256::merge) will produce the
/// same result as hashing 8 elements which make up these digests using
/// [hash_elements()](Rpo256::hash_elements) function.
///
/// However, [hash()](Rpo256::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Rpo256::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Rpo256::hash_elements) function. The reason for
/// this difference is that [hash()](Rpo256::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Rpo256::hash_elements) function rather then hashing the serialized bytes
/// using [hash()](Rpo256::hash) function.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Rpo256();

impl Hasher for Rpo256 {
    /// Rpo256 collision resistance is the same as the security level, that is 128-bits.
    ///
    /// #### Collision resistance
    ///
    /// However, our setup of the capacity registers might drop it to 126.
    ///
    /// Related issue: [#69](https://github.com/0xPolygonMiden/crypto/issues/69)
    const COLLISION_RESISTANCE: u32 = 128;

    type Digest = RpoDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // initialize the state with zeroes
        let mut state = [ZERO; STATE_WIDTH];

        // set the capacity (first element) to a flag on whether or not the input length is evenly
        // divided by the rate. this will prevent collisions between padded and non-padded inputs,
        // and will rule out the need to perform an extra permutation in case of evenly divided
        // inputs.
        let is_rate_multiple = bytes.len() % RATE_WIDTH == 0;
        if !is_rate_multiple {
            state[CAPACITY_RANGE.start] = ONE;
        }

        // initialize a buffer to receive the little-endian elements.
        let mut buf = [0_u8; 8];

        // iterate the chunks of bytes, creating a field element from each chunk and copying it
        // into the state.
        //
        // every time the rate range is filled, a permutation is performed. if the final value of
        // `i` is not zero, then the chunks count wasn't enough to fill the state range, and an
        // additional permutation must be performed.
        let i = bytes.chunks(BINARY_CHUNK_SIZE).fold(0, |i, chunk| {
            // the last element of the iteration may or may not be a full chunk. if it's not, then
            // we need to pad the remainder bytes of the chunk with zeroes, separated by a `1`.
            // this will avoid collisions.
            if chunk.len() == BINARY_CHUNK_SIZE {
                buf[..BINARY_CHUNK_SIZE].copy_from_slice(chunk);
            } else {
                buf.fill(0);
                buf[..chunk.len()].copy_from_slice(chunk);
                buf[chunk.len()] = 1;
            }

            // set the current rate element to the input. since we take at most 7 bytes, we are
            // guaranteed that the inputs data will fit into a single field element.
            state[RATE_RANGE.start + i] = Felt::new(u64::from_le_bytes(buf));

            // proceed filling the range. if it's full, then we apply a permutation and reset the
            // counter to the beginning of the range.
            if i == RATE_WIDTH - 1 {
                Self::apply_permutation(&mut state);
                0
            } else {
                i + 1
            }
        });

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the RPO permutation. we
        // don't need to apply any extra padding because the first capacity element containts a
        // flag indicating whether the input is evenly divisible by the rate.
        if i != 0 {
            state[RATE_RANGE.start + i..RATE_RANGE.end].fill(ZERO);
            state[RATE_RANGE.start + i] = ONE;
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the rate as hash result.
        RpoDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the capacity elements to 0.
        let mut state = [ZERO; STATE_WIDTH];
        let it = Self::Digest::digests_as_elements(values.iter());
        for (i, v) in it.enumerate() {
            state[RATE_RANGE.start + i] = *v;
        }

        // apply the RPO permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        RpoDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        // initialize the state as follows:
        // - seed is copied into the first 4 elements of the rate portion of the state.
        // - if the value fits into a single field element, copy it into the fifth rate element
        //   and set the sixth rate element to 1.
        // - if the value doesn't fit into a single field element, split it into two field
        //   elements, copy them into rate elements 5 and 6, and set the seventh rate element
        //   to 1.
        // - set the first capacity element to 1
        let mut state = [ZERO; STATE_WIDTH];
        state[INPUT1_RANGE].copy_from_slice(seed.as_elements());
        state[INPUT2_RANGE.start] = Felt::new(value);
        if value < Felt::MODULUS {
            state[INPUT2_RANGE.start + 1] = ONE;
        } else {
            state[INPUT2_RANGE.start + 1] = Felt::new(value / Felt::MODULUS);
            state[INPUT2_RANGE.start + 2] = ONE;
        }

        // common padding for both cases
        state[CAPACITY_RANGE.start] = ONE;

        // apply the RPO permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        RpoDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

impl ElementHasher for Rpo256 {
    type BaseField = Felt;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        // convert the elements into a list of base field elements
        let elements = E::slice_as_base_elements(elements);

        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to 1 if the number of elements is not a multiple of RATE_WIDTH.
        let mut state = [ZERO; STATE_WIDTH];
        if elements.len() % RATE_WIDTH != 0 {
            state[CAPACITY_RANGE.start] = ONE;
        }

        // absorb elements into the state one by one until the rate portion of the state is filled
        // up; then apply the Rescue permutation and start absorbing again; repeat until all
        // elements have been absorbed
        let mut i = 0;
        for &element in elements.iter() {
            state[RATE_RANGE.start + i] = element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the RPO permutation after
        // padding by appending a 1 followed by as many 0 as necessary to make the input length a
        // multiple of the RATE_WIDTH.
        if i > 0 {
            state[RATE_RANGE.start + i] = ONE;
            i += 1;
            while i != RATE_WIDTH {
                state[RATE_RANGE.start + i] = ZERO;
                i += 1;
            }
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        RpoDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

// HASH FUNCTION IMPLEMENTATION
// ================================================================================================

impl Rpo256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of rounds is set to 7 to target 128-bit security level.
    pub const NUM_ROUNDS: usize = NUM_ROUNDS;

    /// Sponge state is set to 12 field elements or 768 bytes; 8 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 4 through 11 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The capacity portion of the state is located in elements 0, 1, 2, and 3.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 4, 5, 6, and 7.
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// MDS matrix used for computing the linear layer in a RPO round.
    pub const MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = MDS;

    /// Round constants added to the hasher state in the first half of the RPO round.
    pub const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = ARK1;

    /// Round constants added to the hasher state in the second half of the RPO round.
    pub const ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = ARK2;

    // TRAIT PASS-THROUGH FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> RpoDigest {
        <Self as Hasher>::hash(bytes)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[RpoDigest; 2]) -> RpoDigest {
        <Self as Hasher>::merge(values)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E: FieldElement<BaseField = Felt>>(elements: &[E]) -> RpoDigest {
        <Self as ElementHasher>::hash_elements(elements)
    }

    // DOMAIN IDENTIFIER
    // --------------------------------------------------------------------------------------------

    /// Returns a hash of two digests and a domain identifier.
    pub fn merge_in_domain(values: &[RpoDigest; 2], domain: Felt) -> RpoDigest {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the capacity elements to 0.
        let mut state = [ZERO; STATE_WIDTH];
        let it = RpoDigest::digests_as_elements(values.iter());
        for (i, v) in it.enumerate() {
            state[RATE_RANGE.start + i] = *v;
        }

        // set the second capacity element to the domain value. The first capacity element is used
        // for padding purposes.
        state[CAPACITY_RANGE.start + 1] = domain;

        // apply the RPO permutation and return the first four elements of the state
        Self::apply_permutation(&mut state);
        RpoDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    // RESCUE PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies RPO permutation to the provided state.
    #[inline(always)]
    pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
        for i in 0..NUM_ROUNDS {
            Self::apply_round(state, i);
        }
    }

    /// RPO round function.
    #[inline(always)]
    pub fn apply_round(state: &mut [Felt; STATE_WIDTH], round: usize) {
        // apply first half of RPO round
        apply_mds(state);
        if !optimized_add_constants_and_apply_sbox(state, &ARK1[round]) {
            add_constants(state, &ARK1[round]);
            apply_sbox(state);
        }

        // apply second half of RPO round
        apply_mds(state);
        if !optimized_add_constants_and_apply_inv_sbox(state, &ARK2[round]) {
            add_constants(state, &ARK2[round]);
            apply_inv_sbox(state);
        }
    }
}
