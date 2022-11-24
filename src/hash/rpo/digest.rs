use super::DIGEST_SIZE;
use crate::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Digest, Felt, Serializable,
    StarkField, String, ZERO,
};
use core::ops::Deref;

// DIGEST TRAIT IMPLEMENTATIONS
// ================================================================================================

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RpoDigest256([Felt; DIGEST_SIZE]);

impl RpoDigest256 {
    pub fn new(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }

    pub fn as_elements(&self) -> &[Felt] {
        self.as_ref()
    }

    pub fn digests_as_elements<'a, I>(digests: I) -> impl Iterator<Item = &'a Felt>
    where
        I: Iterator<Item = &'a Self>,
    {
        digests.flat_map(|d| d.0.iter())
    }
}

impl Digest for RpoDigest256 {
    fn as_bytes(&self) -> [u8; 32] {
        let mut result = [0; 32];

        result[..8].copy_from_slice(&self.0[0].as_int().to_le_bytes());
        result[8..16].copy_from_slice(&self.0[1].as_int().to_le_bytes());
        result[16..24].copy_from_slice(&self.0[2].as_int().to_le_bytes());
        result[24..].copy_from_slice(&self.0[3].as_int().to_le_bytes());

        result
    }
}

impl Default for RpoDigest256 {
    fn default() -> Self {
        RpoDigest256([Felt::default(); DIGEST_SIZE])
    }
}

impl Serializable for RpoDigest256 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.as_bytes());
    }
}

impl Deserializable for RpoDigest256 {
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

impl From<[Felt; DIGEST_SIZE]> for RpoDigest256 {
    fn from(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }
}

impl From<RpoDigest256> for [Felt; DIGEST_SIZE] {
    fn from(value: RpoDigest256) -> Self {
        value.0
    }
}

impl From<RpoDigest256> for [u8; 32] {
    fn from(value: RpoDigest256) -> Self {
        value.as_bytes()
    }
}

impl Deref for RpoDigest256 {
    type Target = [Felt; DIGEST_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use super::RpoDigest256;
    use crate::{Deserializable, Felt, Serializable, SliceReader};
    use rand_utils::rand_value;

    #[test]
    fn digest_serialization() {
        let e1 = Felt::new(rand_value());
        let e2 = Felt::new(rand_value());
        let e3 = Felt::new(rand_value());
        let e4 = Felt::new(rand_value());

        let d1 = RpoDigest256([e1, e2, e3, e4]);

        let mut bytes = vec![];
        d1.write_into(&mut bytes);
        assert_eq!(32, bytes.len());

        let mut reader = SliceReader::new(&bytes);
        let d2 = RpoDigest256::read_from(&mut reader).unwrap();

        assert_eq!(d1, d2);
    }
}
