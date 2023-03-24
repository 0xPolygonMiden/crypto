use super::{Digest, ElementHasher, Felt, FieldElement, Hasher, StarkField};
use crate::utils::{
    uninit_vector, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use core::{
    mem::{size_of, transmute, transmute_copy},
    ops::Deref,
    slice::from_raw_parts,
};

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const DIGEST32_BYTES: usize = 32;
const DIGEST24_BYTES: usize = 24;
const DIGEST20_BYTES: usize = 20;

// BLAKE3 N-BIT OUTPUT
// ================================================================================================

/// N-bytes output of a blake3 function.
///
/// Note: `N` can't be greater than `32` because [`Digest::as_bytes`] currently supports only 32
/// bytes.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Blake3Digest<const N: usize>([u8; N]);

impl<const N: usize> Default for Blake3Digest<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> Deref for Blake3Digest<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> From<Blake3Digest<N>> for [u8; N] {
    fn from(value: Blake3Digest<N>) -> Self {
        value.0
    }
}

impl<const N: usize> From<[u8; N]> for Blake3Digest<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> Serializable for Blake3Digest<N> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl<const N: usize> Deserializable for Blake3Digest<N> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_array().map(Self)
    }
}

impl<const N: usize> Digest for Blake3Digest<N> {
    fn as_bytes(&self) -> [u8; 32] {
        // compile-time assertion
        assert!(N <= 32, "digest currently supports only 32 bytes!");
        expand_bytes(&self.0)
    }
}

// BLAKE3 256-BIT OUTPUT
// ================================================================================================

/// 256-bit output blake3 hasher.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Blake3_256;

impl Hasher for Blake3_256 {
    /// Blake3 collision resistance is 128-bits for 32-bytes output.
    const COLLISION_RESISTANCE: u32 = 128;

    type Digest = Blake3Digest<32>;

    fn hash(bytes: &[u8]) -> Self::Digest {
        Blake3Digest(blake3::hash(bytes).into())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Self::hash(prepare_merge(values))
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed.0);
        hasher.update(&value.to_le_bytes());
        Blake3Digest(hasher.finalize().into())
    }
}

impl ElementHasher for Blake3_256 {
    type BaseField = Felt;

    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        Blake3Digest(hash_elements(elements))
    }
}

impl Blake3_256 {
    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Blake3Digest<DIGEST32_BYTES> {
        <Self as Hasher>::hash(bytes)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Blake3Digest<DIGEST32_BYTES>; 2]) -> Blake3Digest<DIGEST32_BYTES> {
        <Self as Hasher>::merge(values)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Blake3Digest<DIGEST32_BYTES>
    where
        E: FieldElement<BaseField = Felt>,
    {
        <Self as ElementHasher>::hash_elements(elements)
    }
}

// BLAKE3 192-BIT OUTPUT
// ================================================================================================

/// 192-bit output blake3 hasher.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Blake3_192;

impl Hasher for Blake3_192 {
    /// Blake3 collision resistance is 96-bits for 24-bytes output.
    const COLLISION_RESISTANCE: u32 = 96;

    type Digest = Blake3Digest<24>;

    fn hash(bytes: &[u8]) -> Self::Digest {
        Blake3Digest(*shrink_bytes(&blake3::hash(bytes).into()))
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Self::hash(prepare_merge(values))
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed.0);
        hasher.update(&value.to_le_bytes());
        Blake3Digest(*shrink_bytes(&hasher.finalize().into()))
    }
}

impl ElementHasher for Blake3_192 {
    type BaseField = Felt;

    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        Blake3Digest(hash_elements(elements))
    }
}

impl Blake3_192 {
    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Blake3Digest<DIGEST24_BYTES> {
        <Self as Hasher>::hash(bytes)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Blake3Digest<DIGEST24_BYTES>; 2]) -> Blake3Digest<DIGEST24_BYTES> {
        <Self as Hasher>::merge(values)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Blake3Digest<DIGEST24_BYTES>
    where
        E: FieldElement<BaseField = Felt>,
    {
        <Self as ElementHasher>::hash_elements(elements)
    }
}

// BLAKE3 160-BIT OUTPUT
// ================================================================================================

/// 160-bit output blake3 hasher.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Blake3_160;

impl Hasher for Blake3_160 {
    /// Blake3 collision resistance is 80-bits for 20-bytes output.
    const COLLISION_RESISTANCE: u32 = 80;

    type Digest = Blake3Digest<20>;

    fn hash(bytes: &[u8]) -> Self::Digest {
        Blake3Digest(*shrink_bytes(&blake3::hash(bytes).into()))
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Self::hash(prepare_merge(values))
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed.0);
        hasher.update(&value.to_le_bytes());
        Blake3Digest(*shrink_bytes(&hasher.finalize().into()))
    }
}

impl ElementHasher for Blake3_160 {
    type BaseField = Felt;

    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        Blake3Digest(hash_elements(elements))
    }
}

impl Blake3_160 {
    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Blake3Digest<DIGEST20_BYTES> {
        <Self as Hasher>::hash(bytes)
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Blake3Digest<DIGEST20_BYTES>; 2]) -> Blake3Digest<DIGEST20_BYTES> {
        <Self as Hasher>::merge(values)
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Blake3Digest<DIGEST20_BYTES>
    where
        E: FieldElement<BaseField = Felt>,
    {
        <Self as ElementHasher>::hash_elements(elements)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Zero-copy ref shrink to array.
fn shrink_bytes<const M: usize, const N: usize>(bytes: &[u8; M]) -> &[u8; N] {
    // compile-time assertion
    assert!(
        M >= N,
        "N should fit in M so it can be safely transmuted into a smaller slice!"
    );
    // safety: bytes len is asserted
    unsafe { transmute(bytes) }
}

/// Hash the elements into bytes and shrink the output.
fn hash_elements<const N: usize, E>(elements: &[E]) -> [u8; N]
where
    E: FieldElement<BaseField = Felt>,
{
    // don't leak assumptions from felt and check its actual implementation.
    // this is a compile-time branch so it is for free
    let digest = if Felt::IS_CANONICAL {
        blake3::hash(E::elements_as_bytes(elements))
    } else {
        let base_elements = E::slice_as_base_elements(elements);
        let blen = base_elements.len() << 3;

        let mut bytes = unsafe { uninit_vector(blen) };
        for (idx, element) in base_elements.iter().enumerate() {
            bytes[idx * 8..(idx + 1) * 8].copy_from_slice(&element.as_int().to_le_bytes());
        }

        blake3::hash(&bytes)
    };
    *shrink_bytes(&digest.into())
}

/// Owned bytes expansion.
fn expand_bytes<const M: usize, const N: usize>(bytes: &[u8; M]) -> [u8; N] {
    // compile-time assertion
    assert!(M <= N, "M should fit in N so M can be expanded!");
    // this branch is constant so it will be optimized to be either one of the variants in release
    // mode
    if M == N {
        // safety: the sizes are checked to be the same
        unsafe { transmute_copy(bytes) }
    } else {
        let mut expanded = [0u8; N];
        expanded[..M].copy_from_slice(bytes);
        expanded
    }
}

// Cast the slice into contiguous bytes.
fn prepare_merge<const N: usize, D>(args: &[D; N]) -> &[u8]
where
    D: Deref<Target = [u8]>,
{
    // compile-time assertion
    assert!(N > 0, "N shouldn't represent an empty slice!");
    let values = args.as_ptr() as *const u8;
    let len = size_of::<D>() * N;
    // safety: the values are tested to be contiguous
    let bytes = unsafe { from_raw_parts(values, len) };
    debug_assert_eq!(args[0].deref(), &bytes[..len / N]);
    bytes
}
