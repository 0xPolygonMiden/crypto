use super::{Digest, ElementHasher, Felt, FieldElement, Hasher, StarkField, ONE, ZERO};
use core::{convert::TryInto, ops::Range};

mod digest;
pub use digest::RpoDigest;

mod mds_freq;
use mds_freq::mds_multiply_freq;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Sponge state is set to 12 field elements or 96 bytes; 8 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
const STATE_WIDTH: usize = 12;

/// The rate portion of the state is located in elements 4 through 11.
const RATE_RANGE: Range<usize> = 4..12;
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

const INPUT1_RANGE: Range<usize> = 4..8;
const INPUT2_RANGE: Range<usize> = 8..12;

/// The capacity portion of the state is located in elements 0, 1, 2, and 3.
const CAPACITY_RANGE: Range<usize> = 0..4;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes.
///
/// The digest is returned from state elements 4, 5, 6, and 7 (the first four elements of the
/// rate portion).
const DIGEST_RANGE: Range<usize> = 4..8;
const DIGEST_SIZE: usize = DIGEST_RANGE.end - DIGEST_RANGE.start;

/// The number of rounds is set to 7 to target 128-bit security level
const NUM_ROUNDS: usize = 7;

/// The number of byte chunks defining a field element when hashing a sequence of bytes
const BINARY_CHUNK_SIZE: usize = 7;

/// S-Box and Inverse S-Box powers;
///
/// The constants are defined for tests only because the exponentiations in the code are unrolled
/// for efficiency reasons.
#[cfg(test)]
const ALPHA: u64 = 7;
#[cfg(test)]
const INV_ALPHA: u64 = 10540996611094048183;

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
        Self::apply_mds(state);
        Self::add_constants(state, &ARK1[round]);
        Self::apply_sbox(state);

        // apply second half of RPO round
        Self::apply_mds(state);
        Self::add_constants(state, &ARK2[round]);
        Self::apply_inv_sbox(state);
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    #[inline(always)]
    fn apply_mds(state: &mut [Felt; STATE_WIDTH]) {
        let mut result = [ZERO; STATE_WIDTH];

        // Using the linearity of the operations we can split the state into a low||high decomposition
        // and operate on each with no overflow and then combine/reduce the result to a field element.
        // The no overflow is guaranteed by the fact that the MDS matrix is a small powers of two in
        // frequency domain.
        let mut state_l = [0u64; STATE_WIDTH];
        let mut state_h = [0u64; STATE_WIDTH];

        for r in 0..STATE_WIDTH {
            let s = state[r].inner();
            state_h[r] = s >> 32;
            state_l[r] = (s as u32) as u64;
        }

        let state_h = mds_multiply_freq(state_h);
        let state_l = mds_multiply_freq(state_l);

        for r in 0..STATE_WIDTH {
            let s = state_l[r] as u128 + ((state_h[r] as u128) << 32);
            let s_hi = (s >> 64) as u64;
            let s_lo = s as u64;
            let z = (s_hi << 32) - s_hi;
            let (res, over) = s_lo.overflowing_add(z);

            result[r] = Felt::from_mont(res.wrapping_add(0u32.wrapping_sub(over as u32) as u64));
        }
        *state = result;
    }

    #[inline(always)]
    fn add_constants(state: &mut [Felt; STATE_WIDTH], ark: &[Felt; STATE_WIDTH]) {
        state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
    }

    #[inline(always)]
    fn apply_sbox(state: &mut [Felt; STATE_WIDTH]) {
        state[0] = state[0].exp7();
        state[1] = state[1].exp7();
        state[2] = state[2].exp7();
        state[3] = state[3].exp7();
        state[4] = state[4].exp7();
        state[5] = state[5].exp7();
        state[6] = state[6].exp7();
        state[7] = state[7].exp7();
        state[8] = state[8].exp7();
        state[9] = state[9].exp7();
        state[10] = state[10].exp7();
        state[11] = state[11].exp7();
    }

    #[inline(always)]
    fn apply_inv_sbox(state: &mut [Felt; STATE_WIDTH]) {
        // compute base^10540996611094048183 using 72 multiplications per array element
        // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111

        // compute base^10
        let mut t1 = *state;
        t1.iter_mut().for_each(|t| *t = t.square());

        // compute base^100
        let mut t2 = t1;
        t2.iter_mut().for_each(|t| *t = t.square());

        // compute base^100100
        let t3 = Self::exp_acc::<Felt, STATE_WIDTH, 3>(t2, t2);

        // compute base^100100100100
        let t4 = Self::exp_acc::<Felt, STATE_WIDTH, 6>(t3, t3);

        // compute base^100100100100100100100100
        let t5 = Self::exp_acc::<Felt, STATE_WIDTH, 12>(t4, t4);

        // compute base^100100100100100100100100100100
        let t6 = Self::exp_acc::<Felt, STATE_WIDTH, 6>(t5, t3);

        // compute base^1001001001001001001001001001000100100100100100100100100100100
        let t7 = Self::exp_acc::<Felt, STATE_WIDTH, 31>(t6, t6);

        // compute base^1001001001001001001001001001000110110110110110110110110110110111
        for (i, s) in state.iter_mut().enumerate() {
            let a = (t7[i].square() * t6[i]).square().square();
            let b = t1[i] * t2[i] * *s;
            *s = a * b;
        }
    }

    #[inline(always)]
    fn exp_acc<B: StarkField, const N: usize, const M: usize>(
        base: [B; N],
        tail: [B; N],
    ) -> [B; N] {
        let mut result = base;
        for _ in 0..M {
            result.iter_mut().for_each(|r| *r = r.square());
        }
        result.iter_mut().zip(tail).for_each(|(r, t)| *r *= t);
        result
    }
}

// MDS
// ================================================================================================
/// RPO MDS matrix
const MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = [
    [
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
    ],
    [
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
    ],
    [
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
    ],
    [
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
    ],
    [
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
    ],
    [
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
    ],
    [
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
    ],
    [
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
    ],
    [
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
    ],
    [
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
        Felt::new(8),
    ],
    [
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
        Felt::new(23),
    ],
    [
        Felt::new(23),
        Felt::new(8),
        Felt::new(26),
        Felt::new(13),
        Felt::new(10),
        Felt::new(9),
        Felt::new(7),
        Felt::new(6),
        Felt::new(22),
        Felt::new(21),
        Felt::new(8),
        Felt::new(7),
    ],
];

// ROUND CONSTANTS
// ================================================================================================

/// Rescue round constants;
/// computed as in [specifications](https://github.com/ASDiscreteMathematics/rpo)
///
/// The constants are broken up into two arrays ARK1 and ARK2; ARK1 contains the constants for the
/// first half of RPO round, and ARK2 contains constants for the second half of RPO round.
const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        Felt::new(5789762306288267392),
        Felt::new(6522564764413701783),
        Felt::new(17809893479458208203),
        Felt::new(107145243989736508),
        Felt::new(6388978042437517382),
        Felt::new(15844067734406016715),
        Felt::new(9975000513555218239),
        Felt::new(3344984123768313364),
        Felt::new(9959189626657347191),
        Felt::new(12960773468763563665),
        Felt::new(9602914297752488475),
        Felt::new(16657542370200465908),
    ],
    [
        Felt::new(12987190162843096997),
        Felt::new(653957632802705281),
        Felt::new(4441654670647621225),
        Felt::new(4038207883745915761),
        Felt::new(5613464648874830118),
        Felt::new(13222989726778338773),
        Felt::new(3037761201230264149),
        Felt::new(16683759727265180203),
        Felt::new(8337364536491240715),
        Felt::new(3227397518293416448),
        Felt::new(8110510111539674682),
        Felt::new(2872078294163232137),
    ],
    [
        Felt::new(18072785500942327487),
        Felt::new(6200974112677013481),
        Felt::new(17682092219085884187),
        Felt::new(10599526828986756440),
        Felt::new(975003873302957338),
        Felt::new(8264241093196931281),
        Felt::new(10065763900435475170),
        Felt::new(2181131744534710197),
        Felt::new(6317303992309418647),
        Felt::new(1401440938888741532),
        Felt::new(8884468225181997494),
        Felt::new(13066900325715521532),
    ],
    [
        Felt::new(5674685213610121970),
        Felt::new(5759084860419474071),
        Felt::new(13943282657648897737),
        Felt::new(1352748651966375394),
        Felt::new(17110913224029905221),
        Felt::new(1003883795902368422),
        Felt::new(4141870621881018291),
        Felt::new(8121410972417424656),
        Felt::new(14300518605864919529),
        Felt::new(13712227150607670181),
        Felt::new(17021852944633065291),
        Felt::new(6252096473787587650),
    ],
    [
        Felt::new(4887609836208846458),
        Felt::new(3027115137917284492),
        Felt::new(9595098600469470675),
        Felt::new(10528569829048484079),
        Felt::new(7864689113198939815),
        Felt::new(17533723827845969040),
        Felt::new(5781638039037710951),
        Felt::new(17024078752430719006),
        Felt::new(109659393484013511),
        Felt::new(7158933660534805869),
        Felt::new(2955076958026921730),
        Felt::new(7433723648458773977),
    ],
    [
        Felt::new(16308865189192447297),
        Felt::new(11977192855656444890),
        Felt::new(12532242556065780287),
        Felt::new(14594890931430968898),
        Felt::new(7291784239689209784),
        Felt::new(5514718540551361949),
        Felt::new(10025733853830934803),
        Felt::new(7293794580341021693),
        Felt::new(6728552937464861756),
        Felt::new(6332385040983343262),
        Felt::new(13277683694236792804),
        Felt::new(2600778905124452676),
    ],
    [
        Felt::new(7123075680859040534),
        Felt::new(1034205548717903090),
        Felt::new(7717824418247931797),
        Felt::new(3019070937878604058),
        Felt::new(11403792746066867460),
        Felt::new(10280580802233112374),
        Felt::new(337153209462421218),
        Felt::new(13333398568519923717),
        Felt::new(3596153696935337464),
        Felt::new(8104208463525993784),
        Felt::new(14345062289456085693),
        Felt::new(17036731477169661256),
    ],
];

const ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = [
    [
        Felt::new(6077062762357204287),
        Felt::new(15277620170502011191),
        Felt::new(5358738125714196705),
        Felt::new(14233283787297595718),
        Felt::new(13792579614346651365),
        Felt::new(11614812331536767105),
        Felt::new(14871063686742261166),
        Felt::new(10148237148793043499),
        Felt::new(4457428952329675767),
        Felt::new(15590786458219172475),
        Felt::new(10063319113072092615),
        Felt::new(14200078843431360086),
    ],
    [
        Felt::new(6202948458916099932),
        Felt::new(17690140365333231091),
        Felt::new(3595001575307484651),
        Felt::new(373995945117666487),
        Felt::new(1235734395091296013),
        Felt::new(14172757457833931602),
        Felt::new(707573103686350224),
        Felt::new(15453217512188187135),
        Felt::new(219777875004506018),
        Felt::new(17876696346199469008),
        Felt::new(17731621626449383378),
        Felt::new(2897136237748376248),
    ],
    [
        Felt::new(8023374565629191455),
        Felt::new(15013690343205953430),
        Felt::new(4485500052507912973),
        Felt::new(12489737547229155153),
        Felt::new(9500452585969030576),
        Felt::new(2054001340201038870),
        Felt::new(12420704059284934186),
        Felt::new(355990932618543755),
        Felt::new(9071225051243523860),
        Felt::new(12766199826003448536),
        Felt::new(9045979173463556963),
        Felt::new(12934431667190679898),
    ],
    [
        Felt::new(18389244934624494276),
        Felt::new(16731736864863925227),
        Felt::new(4440209734760478192),
        Felt::new(17208448209698888938),
        Felt::new(8739495587021565984),
        Felt::new(17000774922218161967),
        Felt::new(13533282547195532087),
        Felt::new(525402848358706231),
        Felt::new(16987541523062161972),
        Felt::new(5466806524462797102),
        Felt::new(14512769585918244983),
        Felt::new(10973956031244051118),
    ],
    [
        Felt::new(6982293561042362913),
        Felt::new(14065426295947720331),
        Felt::new(16451845770444974180),
        Felt::new(7139138592091306727),
        Felt::new(9012006439959783127),
        Felt::new(14619614108529063361),
        Felt::new(1394813199588124371),
        Felt::new(4635111139507788575),
        Felt::new(16217473952264203365),
        Felt::new(10782018226466330683),
        Felt::new(6844229992533662050),
        Felt::new(7446486531695178711),
    ],
    [
        Felt::new(3736792340494631448),
        Felt::new(577852220195055341),
        Felt::new(6689998335515779805),
        Felt::new(13886063479078013492),
        Felt::new(14358505101923202168),
        Felt::new(7744142531772274164),
        Felt::new(16135070735728404443),
        Felt::new(12290902521256031137),
        Felt::new(12059913662657709804),
        Felt::new(16456018495793751911),
        Felt::new(4571485474751953524),
        Felt::new(17200392109565783176),
    ],
    [
        Felt::new(17130398059294018733),
        Felt::new(519782857322261988),
        Felt::new(9625384390925085478),
        Felt::new(1664893052631119222),
        Felt::new(7629576092524553570),
        Felt::new(3485239601103661425),
        Felt::new(9755891797164033838),
        Felt::new(15218148195153269027),
        Felt::new(16460604813734957368),
        Felt::new(9643968136937729763),
        Felt::new(3611348709641382851),
        Felt::new(18256379591337759196),
    ],
];
