use super::{Digest, Felt, StarkField, DIGEST_SIZE, ZERO};
use crate::utils::{
    string::String, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use core::{cmp::Ordering, ops::Deref};

// DIGEST TRAIT IMPLEMENTATIONS
// ================================================================================================

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct RpoDigest([Felt; DIGEST_SIZE]);

impl RpoDigest {
    pub const fn new(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }

    pub fn as_elements(&self) -> &[Felt] {
        self.as_ref()
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        <Self as Digest>::as_bytes(self)
    }

    pub fn digests_as_elements<'a, I>(digests: I) -> impl Iterator<Item = &'a Felt>
    where
        I: Iterator<Item = &'a Self>,
    {
        digests.flat_map(|d| d.0.iter())
    }
}

impl Digest for RpoDigest {
    fn as_bytes(&self) -> [u8; 32] {
        let mut result = [0; 32];

        result[..8].copy_from_slice(&self.0[0].as_int().to_le_bytes());
        result[8..16].copy_from_slice(&self.0[1].as_int().to_le_bytes());
        result[16..24].copy_from_slice(&self.0[2].as_int().to_le_bytes());
        result[24..].copy_from_slice(&self.0[3].as_int().to_le_bytes());

        result
    }
}

impl Serializable for RpoDigest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.as_bytes());
    }
}

impl Deserializable for RpoDigest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut inner: [Felt; DIGEST_SIZE] = [ZERO; DIGEST_SIZE];
        for inner in inner.iter_mut() {
            let e = source.read_u64()?;
            if e >= Felt::MODULUS {
                return Err(DeserializationError::InvalidValue(String::from(
                    "Value not in the appropriate range",
                )));
            }
            *inner = Felt::new(e);
        }

        Ok(Self(inner))
    }
}

impl From<[Felt; DIGEST_SIZE]> for RpoDigest {
    fn from(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }
}

impl From<&RpoDigest> for [Felt; DIGEST_SIZE] {
    fn from(value: &RpoDigest) -> Self {
        value.0
    }
}

impl From<RpoDigest> for [Felt; DIGEST_SIZE] {
    fn from(value: RpoDigest) -> Self {
        value.0
    }
}

impl From<&RpoDigest> for [u8; 32] {
    fn from(value: &RpoDigest) -> Self {
        value.as_bytes()
    }
}

impl From<RpoDigest> for [u8; 32] {
    fn from(value: RpoDigest) -> Self {
        value.as_bytes()
    }
}

impl Deref for RpoDigest {
    type Target = [Felt; DIGEST_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ord for RpoDigest {
    fn cmp(&self, other: &Self) -> Ordering {
        // compare the inner u64 of both elements.
        //
        // it will iterate the elements and will return the first computation different than
        // `Equal`. Otherwise, the ordering is equal.
        //
        // the endianness is irrelevant here because since, this being a cryptographically secure
        // hash computation, the digest shouldn't have any ordered property of its input.
        //
        // finally, we use `Felt::inner` instead of `Felt::as_int` so we avoid performing a
        // montgomery reduction for every limb. that is safe because every inner element of the
        // digest is guaranteed to be in its canonical form (that is, `x in [0,p)`).
        self.0
            .iter()
            .map(Felt::inner)
            .zip(other.0.iter().map(Felt::inner))
            .fold(Ordering::Equal, |ord, (a, b)| match ord {
                Ordering::Equal => a.cmp(&b),
                _ => ord,
            })
    }
}

impl PartialOrd for RpoDigest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use super::{Deserializable, Felt, RpoDigest, Serializable};
    use crate::utils::SliceReader;
    use rand_utils::rand_value;

    #[test]
    fn digest_serialization() {
        let e1 = Felt::new(rand_value());
        let e2 = Felt::new(rand_value());
        let e3 = Felt::new(rand_value());
        let e4 = Felt::new(rand_value());

        let d1 = RpoDigest([e1, e2, e3, e4]);

        let mut bytes = vec![];
        d1.write_into(&mut bytes);
        assert_eq!(32, bytes.len());

        let mut reader = SliceReader::new(&bytes);
        let d2 = RpoDigest::read_from(&mut reader).unwrap();

        assert_eq!(d1, d2);
    }
}
