use super::{Digest, Felt, StarkField, DIGEST_BYTES, DIGEST_SIZE, ZERO};
use crate::utils::{
    bytes_to_hex_string, hex_to_bytes, string::String, ByteReader, ByteWriter, Deserializable,
    DeserializationError, HexParseError, Serializable,
};
use core::{cmp::Ordering, fmt::Display, ops::Deref};
use winter_utils::Randomizable;

// DIGEST TRAIT IMPLEMENTATIONS
// ================================================================================================

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "String", try_from = "&str"))]
pub struct RpxDigest([Felt; DIGEST_SIZE]);

impl RpxDigest {
    pub const fn new(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }

    pub fn as_elements(&self) -> &[Felt] {
        self.as_ref()
    }

    pub fn as_bytes(&self) -> [u8; DIGEST_BYTES] {
        <Self as Digest>::as_bytes(self)
    }

    pub fn digests_as_elements<'a, I>(digests: I) -> impl Iterator<Item = &'a Felt>
    where
        I: Iterator<Item = &'a Self>,
    {
        digests.flat_map(|d| d.0.iter())
    }

    /// Returns hexadecimal representation of this digest prefixed with `0x`.
    pub fn to_hex(&self) -> String {
        bytes_to_hex_string(self.as_bytes())
    }
}

impl Digest for RpxDigest {
    fn as_bytes(&self) -> [u8; DIGEST_BYTES] {
        let mut result = [0; DIGEST_BYTES];

        result[..8].copy_from_slice(&self.0[0].as_int().to_le_bytes());
        result[8..16].copy_from_slice(&self.0[1].as_int().to_le_bytes());
        result[16..24].copy_from_slice(&self.0[2].as_int().to_le_bytes());
        result[24..].copy_from_slice(&self.0[3].as_int().to_le_bytes());

        result
    }
}

impl Deref for RpxDigest {
    type Target = [Felt; DIGEST_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ord for RpxDigest {
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
        self.0.iter().map(Felt::inner).zip(other.0.iter().map(Felt::inner)).fold(
            Ordering::Equal,
            |ord, (a, b)| match ord {
                Ordering::Equal => a.cmp(&b),
                _ => ord,
            },
        )
    }
}

impl PartialOrd for RpxDigest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for RpxDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let encoded: String = self.into();
        write!(f, "{}", encoded)?;
        Ok(())
    }
}

impl Randomizable for RpxDigest {
    const VALUE_SIZE: usize = DIGEST_BYTES;

    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes_array: Option<[u8; 32]> = bytes.try_into().ok();
        if let Some(bytes_array) = bytes_array {
            Self::try_from(bytes_array).ok()
        } else {
            None
        }
    }
}

// CONVERSIONS: FROM RPX DIGEST
// ================================================================================================

impl From<&RpxDigest> for [Felt; DIGEST_SIZE] {
    fn from(value: &RpxDigest) -> Self {
        value.0
    }
}

impl From<RpxDigest> for [Felt; DIGEST_SIZE] {
    fn from(value: RpxDigest) -> Self {
        value.0
    }
}

impl From<&RpxDigest> for [u64; DIGEST_SIZE] {
    fn from(value: &RpxDigest) -> Self {
        [
            value.0[0].as_int(),
            value.0[1].as_int(),
            value.0[2].as_int(),
            value.0[3].as_int(),
        ]
    }
}

impl From<RpxDigest> for [u64; DIGEST_SIZE] {
    fn from(value: RpxDigest) -> Self {
        [
            value.0[0].as_int(),
            value.0[1].as_int(),
            value.0[2].as_int(),
            value.0[3].as_int(),
        ]
    }
}

impl From<&RpxDigest> for [u8; DIGEST_BYTES] {
    fn from(value: &RpxDigest) -> Self {
        value.as_bytes()
    }
}

impl From<RpxDigest> for [u8; DIGEST_BYTES] {
    fn from(value: RpxDigest) -> Self {
        value.as_bytes()
    }
}

impl From<RpxDigest> for String {
    /// The returned string starts with `0x`.
    fn from(value: RpxDigest) -> Self {
        value.to_hex()
    }
}

impl From<&RpxDigest> for String {
    /// The returned string starts with `0x`.
    fn from(value: &RpxDigest) -> Self {
        (*value).into()
    }
}

// CONVERSIONS: TO RPX DIGEST
// ================================================================================================

#[derive(Copy, Clone, Debug)]
pub enum RpxDigestError {
    /// The provided u64 integer does not fit in the field's moduli.
    InvalidInteger,
}

impl From<&[Felt; DIGEST_SIZE]> for RpxDigest {
    fn from(value: &[Felt; DIGEST_SIZE]) -> Self {
        Self(*value)
    }
}

impl From<[Felt; DIGEST_SIZE]> for RpxDigest {
    fn from(value: [Felt; DIGEST_SIZE]) -> Self {
        Self(value)
    }
}

impl TryFrom<[u8; DIGEST_BYTES]> for RpxDigest {
    type Error = HexParseError;

    fn try_from(value: [u8; DIGEST_BYTES]) -> Result<Self, Self::Error> {
        // Note: the input length is known, the conversion from slice to array must succeed so the
        // `unwrap`s below are safe
        let a = u64::from_le_bytes(value[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(value[8..16].try_into().unwrap());
        let c = u64::from_le_bytes(value[16..24].try_into().unwrap());
        let d = u64::from_le_bytes(value[24..32].try_into().unwrap());

        if [a, b, c, d].iter().any(|v| *v >= Felt::MODULUS) {
            return Err(HexParseError::OutOfRange);
        }

        Ok(RpxDigest([Felt::new(a), Felt::new(b), Felt::new(c), Felt::new(d)]))
    }
}

impl TryFrom<&[u8; DIGEST_BYTES]> for RpxDigest {
    type Error = HexParseError;

    fn try_from(value: &[u8; DIGEST_BYTES]) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<&[u8]> for RpxDigest {
    type Error = HexParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<[u64; DIGEST_SIZE]> for RpxDigest {
    type Error = RpxDigestError;

    fn try_from(value: [u64; DIGEST_SIZE]) -> Result<Self, RpxDigestError> {
        if value[0] >= Felt::MODULUS
            || value[1] >= Felt::MODULUS
            || value[2] >= Felt::MODULUS
            || value[3] >= Felt::MODULUS
        {
            return Err(RpxDigestError::InvalidInteger);
        }

        Ok(Self([value[0].into(), value[1].into(), value[2].into(), value[3].into()]))
    }
}

impl TryFrom<&[u64; DIGEST_SIZE]> for RpxDigest {
    type Error = RpxDigestError;

    fn try_from(value: &[u64; DIGEST_SIZE]) -> Result<Self, RpxDigestError> {
        (*value).try_into()
    }
}

impl TryFrom<&str> for RpxDigest {
    type Error = HexParseError;

    /// Expects the string to start with `0x`.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex_to_bytes(value).and_then(|v| v.try_into())
    }
}

impl TryFrom<String> for RpxDigest {
    type Error = HexParseError;

    /// Expects the string to start with `0x`.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&String> for RpxDigest {
    type Error = HexParseError;

    /// Expects the string to start with `0x`.
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for RpxDigest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.as_bytes());
    }
}

impl Deserializable for RpxDigest {
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{Deserializable, Felt, RpxDigest, Serializable, DIGEST_BYTES, DIGEST_SIZE};
    use crate::utils::{string::String, SliceReader};
    use rand_utils::rand_value;

    #[test]
    fn digest_serialization() {
        let e1 = Felt::new(rand_value());
        let e2 = Felt::new(rand_value());
        let e3 = Felt::new(rand_value());
        let e4 = Felt::new(rand_value());

        let d1 = RpxDigest([e1, e2, e3, e4]);

        let mut bytes = vec![];
        d1.write_into(&mut bytes);
        assert_eq!(DIGEST_BYTES, bytes.len());

        let mut reader = SliceReader::new(&bytes);
        let d2 = RpxDigest::read_from(&mut reader).unwrap();

        assert_eq!(d1, d2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn digest_encoding() {
        let digest = RpxDigest([
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
        ]);

        let string: String = digest.into();
        let round_trip: RpxDigest = string.try_into().expect("decoding failed");

        assert_eq!(digest, round_trip);
    }

    #[test]
    fn test_conversions() {
        let digest = RpxDigest([
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
            Felt::new(rand_value()),
        ]);

        let v: [Felt; DIGEST_SIZE] = digest.into();
        let v2: RpxDigest = v.into();
        assert_eq!(digest, v2);

        let v: [Felt; DIGEST_SIZE] = (&digest).into();
        let v2: RpxDigest = v.into();
        assert_eq!(digest, v2);

        let v: [u64; DIGEST_SIZE] = digest.into();
        let v2: RpxDigest = v.try_into().unwrap();
        assert_eq!(digest, v2);

        let v: [u64; DIGEST_SIZE] = (&digest).into();
        let v2: RpxDigest = v.try_into().unwrap();
        assert_eq!(digest, v2);

        let v: [u8; DIGEST_BYTES] = digest.into();
        let v2: RpxDigest = v.try_into().unwrap();
        assert_eq!(digest, v2);

        let v: [u8; DIGEST_BYTES] = (&digest).into();
        let v2: RpxDigest = v.try_into().unwrap();
        assert_eq!(digest, v2);

        let v: String = digest.into();
        let v2: RpxDigest = v.try_into().unwrap();
        assert_eq!(digest, v2);

        let v: String = (&digest).into();
        let v2: RpxDigest = v.try_into().unwrap();
        assert_eq!(digest, v2);

        let v: [u8; DIGEST_BYTES] = digest.into();
        let v2: RpxDigest = (&v).try_into().unwrap();
        assert_eq!(digest, v2);

        let v: [u8; DIGEST_BYTES] = (&digest).into();
        let v2: RpxDigest = (&v).try_into().unwrap();
        assert_eq!(digest, v2);
    }
}
