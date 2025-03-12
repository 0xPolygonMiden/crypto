/// Iterate over the bits of a `usize` and yields the bit positions for the true bits.
pub struct TrueBitPositionIterator {
    value: usize,
}

impl TrueBitPositionIterator {
    pub fn new(value: usize) -> TrueBitPositionIterator {
        TrueBitPositionIterator { value }
    }
}

impl Iterator for TrueBitPositionIterator {
    type Item = u32;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        // trailing_zeros is computed with the intrinsic cttz. [Rust 1.67.0] x86 uses the `bsf`
        // instruction. AArch64 uses the `rbit clz` instructions.
        let zeros = self.value.trailing_zeros();

        if zeros == usize::BITS {
            None
        } else {
            let bit_position = zeros;
            let mask = 1 << bit_position;
            self.value ^= mask;
            Some(bit_position)
        }
    }
}

impl DoubleEndedIterator for TrueBitPositionIterator {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        // trailing_zeros is computed with the intrinsic ctlz. [Rust 1.67.0] x86 uses the `bsr`
        // instruction. AArch64 uses the `clz` instruction.
        let zeros = self.value.leading_zeros();

        if zeros == usize::BITS {
            None
        } else {
            let bit_position = usize::BITS - zeros - 1;
            let mask = 1 << bit_position;
            self.value ^= mask;
            Some(bit_position)
        }
    }
}
