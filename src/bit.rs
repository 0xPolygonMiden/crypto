/// Yields the bits of a `u64`.
pub struct BitIterator {
    /// The value that is being iterated bit-wise
    value: u64,
    /// True bits in the `mask` are the bits that have been visited.
    mask: u64,
}

impl BitIterator {
    pub fn new(value: u64) -> BitIterator {
        BitIterator { value, mask: 0 }
    }

    /// An efficient skip implementation.
    ///
    /// Note: The compiler is smart enough to translate a `skip(n)` into a single shift instruction
    /// if the code is inlined, however inlining does not always happen.
    pub fn skip_front(mut self, n: u32) -> Self {
        let mask = bitmask(n);
        let ones = self.mask.trailing_ones();
        let mask_position = ones;
        self.mask ^= mask.checked_shl(mask_position).unwrap_or(0);
        self
    }

    /// An efficient skip from the back.
    ///
    /// Note: The compiler is smart enough to translate a `skip(n)` into a single shift instruction
    /// if the code is inlined, however inlining does not always happen.
    pub fn skip_back(mut self, n: u32) -> Self {
        let mask = bitmask(n);
        let ones = self.mask.leading_ones();
        let mask_position = u64::BITS - ones - n;
        self.mask ^= mask.checked_shl(mask_position).unwrap_or(0);
        self
    }
}

impl Iterator for BitIterator {
    type Item = bool;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        // trailing_ones is implemented with trailing_zeros, and the zeros are computed with the
        // intrinsic cttz. [Rust 1.67.0] x86 uses the `bsf` instruction. AArch64 uses the `rbit
        // clz` instructions.
        let ones = self.mask.trailing_ones();

        if ones == u64::BITS {
            None
        } else {
            let bit_position = ones;
            let mask = 1 << bit_position;
            self.mask ^= mask;
            let bit = self.value & mask;
            Some(bit != 0)
        }
    }
}

impl DoubleEndedIterator for BitIterator {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        // leading_ones is implemented with leading_zeros, and the zeros are computed with the
        // intrinsic ctlz. [Rust 1.67.0] x86 uses the `bsr` instruction. AArch64 uses the `clz`
        // instruction.
        let ones = self.mask.leading_ones();

        if ones == u64::BITS {
            None
        } else {
            let bit_position = u64::BITS - ones - 1;
            let mask = 1 << bit_position;
            self.mask ^= mask;
            let bit = self.value & mask;
            Some(bit != 0)
        }
    }
}

#[cfg(test)]
mod test {
    use super::BitIterator;

    #[test]
    fn test_bit_iterator() {
        let v = 0b1;
        let mut it = BitIterator::new(v);
        assert!(it.next().unwrap(), "first bit is true");
        assert!(it.all(|v| v == false), "every other value is false");

        let v = 0b10;
        let mut it = BitIterator::new(v);
        assert!(!it.next().unwrap(), "first bit is false");
        assert!(it.next().unwrap(), "first bit is true");
        assert!(it.all(|v| v == false), "every other value is false");

        let v = 0b10;
        let mut it = BitIterator::new(v);
        assert!(!it.next_back().unwrap(), "last bit is false");
        assert!(!it.next().unwrap(), "first bit is false");
        assert!(it.next().unwrap(), "first bit is true");
        assert!(it.all(|v| v == false), "every other value is false");
    }

    #[test]
    fn test_bit_iterator_skip() {
        let v = 0b1;
        let mut it = BitIterator::new(v).skip_front(1);
        assert!(it.all(|v| v == false), "every other value is false");

        let v = 0b10;
        let mut it = BitIterator::new(v).skip_front(1);
        assert!(it.next().unwrap(), "first bit is true");
        assert!(it.all(|v| v == false), "every other value is false");

        let high_bit = 0b1 << (u64::BITS - 1);
        let mut it = BitIterator::new(high_bit).skip_back(1);
        assert!(it.all(|v| v == false), "every other value is false");

        let v = 0b10;
        let mut it = BitIterator::new(v).skip_back(1);
        assert!(!it.next_back().unwrap(), "last bit is false");
        assert!(!it.next().unwrap(), "first bit is false");
        assert!(it.next().unwrap(), "first bit is true");
        assert!(it.all(|v| v == false), "every other value is false");
    }

    #[test]
    fn test_skip_all() {
        let v = 0b1;
        let mut it = BitIterator::new(v).skip_front(u64::BITS);
        assert!(it.next().is_none(), "iterator must be exhausted");

        let v = 0b1;
        let mut it = BitIterator::new(v).skip_back(u64::BITS);
        assert!(it.next().is_none(), "iterator must be exhausted");
    }

    #[test]
    fn test_bit_iterator_count_bits_after_skip() {
        let any_value = 0b1;
        for s in 0..u64::BITS {
            let it = BitIterator::new(any_value).skip_front(s);
            assert_eq!(it.count() as u32, u64::BITS - s)
        }

        let any_value = 0b1;
        for s in 1..u64::BITS {
            let it = BitIterator::new(any_value).skip_back(s);
            assert_eq!(it.count() as u32, u64::BITS - s)
        }
    }

    #[test]
    fn test_bit_iterator_rev() {
        let v = 0b1;
        let mut it = BitIterator::new(v).rev();
        assert!(it.nth(63).unwrap(), "the last value is true");
    }
}

// UTILITIES
// ===============================================================================================

fn bitmask(s: u32) -> u64 {
    match 1u64.checked_shl(s) {
        Some(r) => r - 1,
        None => u64::MAX,
    }
}
