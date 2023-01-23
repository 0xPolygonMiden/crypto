use super::{Felt, RpoDigest, TieredSmt, TreeIndex};

pub struct BitsIterator<'a> {
    elements: &'a [Felt],
    idx: usize,
    bit: u64,
}

impl<'a> From<&'a RpoDigest> for BitsIterator<'a> {
    fn from(value: &'a RpoDigest) -> Self {
        Self {
            elements: value.as_elements(),
            idx: 0,
            bit: 0,
        }
    }
}

impl<'a> Iterator for BitsIterator<'a> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bit == 64 {
            self.idx += 1;
            self.bit = 0;
        }
        let value = match self.elements.get(self.idx) {
            Some(value) => value,
            None => return None,
        };
        let value = value.inner() >> (63 - self.bit);
        let value = value & 1;
        self.bit += 1;
        Some(value == 1)
    }
}

impl<'a> BitsIterator<'a> {
    /// Traverse the index to the next tier.
    ///
    /// Will return `None` if the next depth is beyond the tree maximum, or if the bits are
    /// depleted.
    pub fn traverse<I>(mut index: TreeIndex, mut bits: I) -> Option<TreeIndex>
    where
        I: Iterator<Item = bool>,
    {
        if index.depth() >= TieredSmt::MAX_DEPTH as u32 {
            return None;
        }
        for _ in 0..TieredSmt::TIER_DEPTH {
            index = match bits.next() {
                Some(bit) => index.traverse(bit),
                None => return None,
            };
        }
        Some(index)
    }

    pub fn traverse_from_root<I>(bits: I) -> TreeIndex
    where
        I: Iterator<Item = bool>,
    {
        bits.take(TieredSmt::TIER_DEPTH)
            .fold(TreeIndex::root(), |index, bit| index.traverse(bit))
    }
}
