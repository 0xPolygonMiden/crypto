use super::{get_key_prefix, is_leaf_node, BTreeMap, NodeIndex, RpoDigest, StarkField, Vec, Word};
use crate::utils::vec;
use core::{
    cmp::{Ord, Ordering},
    ops::RangeBounds,
};
use winter_utils::collections::btree_map::Entry;

// CONSTANTS
// ================================================================================================

/// Depths at which leaves can exist in a tiered SMT.
const TIER_DEPTHS: [u8; 4] = super::TieredSmt::TIER_DEPTHS;

/// Maximum node depth. This is also the bottom tier of the tree.
const MAX_DEPTH: u8 = super::TieredSmt::MAX_DEPTH;

// VALUE STORE
// ================================================================================================
/// A store for key-value pairs for a Tiered Sparse Merkle tree.
///
/// The store is organized in a [BTreeMap] where keys are 64 most significant bits of a key, and
/// the values are the corresponding key-value pairs (or a list of key-value pairs if more that
/// a single key-value pair shares the same 64-bit prefix).
///
/// The store supports lookup by the full key as well as by the 64-bit key prefix.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ValueStore {
    values: BTreeMap<u64, StoreEntry>,
}

impl ValueStore {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the value stored under the specified key, or None if there is no
    /// value associated with the specified key.
    pub fn get(&self, key: &RpoDigest) -> Option<&Word> {
        let prefix = get_key_prefix(key);
        self.values.get(&prefix).and_then(|entry| entry.get(key))
    }

    /// Returns the first key-value pair such that the key prefix is greater than or equal to the
    /// specified prefix.
    pub fn get_first(&self, prefix: u64) -> Option<&(RpoDigest, Word)> {
        self.range(prefix..).next()
    }

    /// Returns the first key-value pair such that the key prefix is greater than or equal to the
    /// specified prefix and the key value is not equal to the exclude_key value.
    pub fn get_first_filtered(
        &self,
        prefix: u64,
        exclude_key: &RpoDigest,
    ) -> Option<&(RpoDigest, Word)> {
        self.range(prefix..).find(|(key, _)| key != exclude_key)
    }

    /// Returns a vector with key-value pairs for all keys with the specified 64-bit prefix, or
    /// None if no keys with the specified prefix are present in this store.
    pub fn get_all(&self, prefix: u64) -> Option<Vec<(RpoDigest, Word)>> {
        self.values.get(&prefix).map(|entry| match entry {
            StoreEntry::Single(kv_pair) => vec![*kv_pair],
            StoreEntry::List(kv_pairs) => kv_pairs.clone(),
        })
    }

    /// Returns information about a sibling of a leaf node with the specified index, but only if
    /// this is the only sibling the leaf has in some subtree starting at the first tier.
    ///
    /// For example, if `index` is an index at depth 32, and there is a leaf node at depth 32 with
    /// the same root at depth 16 as `index`, we say that this leaf is a lone sibling.
    ///
    /// The returned tuple contains: they key-value pair of the sibling as well as the index of
    /// the node for the root of the common subtree in which both nodes are leaves.
    ///
    /// This method assumes that the key-value pair for the specified index has already been
    /// removed from the store.
    pub fn get_lone_sibling(&self, index: NodeIndex) -> Option<(&RpoDigest, &Word, NodeIndex)> {
        debug_assert!(is_leaf_node(&index));

        // iterate over tiers from top to bottom, looking at the tiers which are strictly above
        // the depth of the index. This implies that only tiers at depth 32 and 48 will be
        // considered. For each tier, check if the parent of the index at the higher tier
        // contains a single node.
        for &tier in TIER_DEPTHS.iter().filter(|&t| index.depth() > *t) {
            // compute the index of the root at a higher tier
            let mut parent_index = index;
            parent_index.move_up_to(tier);

            // find the lone sibling, if any; we need to handle the "last node" at a given tier
            // separately specify the bounds for the search correctly.
            let start_prefix = parent_index.value() << (MAX_DEPTH - tier);
            let sibling = if start_prefix.leading_ones() as u8 == tier {
                let mut iter = self.range(start_prefix..);
                iter.next().filter(|_| iter.next().is_none())
            } else {
                let end_prefix = (parent_index.value() + 1) << (MAX_DEPTH - tier);
                let mut iter = self.range(start_prefix..end_prefix);
                iter.next().filter(|_| iter.next().is_none())
            };

            if let Some((key, value)) = sibling {
                return Some((key, value, parent_index));
            }
        }

        None
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts the specified key-value pair into this store and returns the value previously
    /// associated with the specified key.
    ///
    /// If no value was previously associated with the specified key, None is returned.
    pub fn insert(&mut self, key: RpoDigest, value: Word) -> Option<Word> {
        let prefix = get_key_prefix(&key);
        match self.values.entry(prefix) {
            Entry::Occupied(mut entry) => entry.get_mut().insert(key, value),
            Entry::Vacant(entry) => {
                entry.insert(StoreEntry::new(key, value));
                None
            }
        }
    }

    /// Removes the key-value pair for the specified key from this store and returns the value
    /// associated with this key.
    ///
    /// If no value was associated with the specified key, None is returned.
    pub fn remove(&mut self, key: &RpoDigest) -> Option<Word> {
        let prefix = get_key_prefix(key);
        match self.values.entry(prefix) {
            Entry::Occupied(mut entry) => {
                let (value, remove_entry) = entry.get_mut().remove(key);
                if remove_entry {
                    entry.remove_entry();
                }
                value
            }
            Entry::Vacant(_) => None,
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over all key-value pairs contained in this store such that the most
    /// significant 64 bits of the key lay within the specified bounds.
    ///
    /// The order of iteration is from the smallest to the largest key.
    fn range<R: RangeBounds<u64>>(&self, bounds: R) -> impl Iterator<Item = &(RpoDigest, Word)> {
        self.values.range(bounds).flat_map(|(_, entry)| entry.iter())
    }
}

// VALUE NODE
// ================================================================================================

/// An entry in the [ValueStore].
///
/// An entry can contain either a single key-value pair or a vector of key-value pairs sorted by
/// key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreEntry {
    Single((RpoDigest, Word)),
    List(Vec<(RpoDigest, Word)>),
}

impl StoreEntry {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [StoreEntry] instantiated with a single key-value pair.
    pub fn new(key: RpoDigest, value: Word) -> Self {
        Self::Single((key, value))
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the value associated with the specified key, or None if this entry does not contain
    /// a value associated with the specified key.
    pub fn get(&self, key: &RpoDigest) -> Option<&Word> {
        match self {
            StoreEntry::Single(kv_pair) => {
                if kv_pair.0 == *key {
                    Some(&kv_pair.1)
                } else {
                    None
                }
            }
            StoreEntry::List(kv_pairs) => {
                match kv_pairs.binary_search_by(|kv_pair| cmp_digests(&kv_pair.0, key)) {
                    Ok(pos) => Some(&kv_pairs[pos].1),
                    Err(_) => None,
                }
            }
        }
    }

    /// Returns an iterator over all key-value pairs in this entry.
    pub fn iter(&self) -> impl Iterator<Item = &(RpoDigest, Word)> {
        EntryIterator {
            entry: self,
            pos: 0,
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts the specified key-value pair into this entry and returns the value previously
    /// associated with the specified key, or None if no value was associated with the specified
    /// key.
    ///
    /// If a new key is inserted, this will also transform a `SingleEntry` into a `ListEntry`.
    pub fn insert(&mut self, key: RpoDigest, value: Word) -> Option<Word> {
        match self {
            StoreEntry::Single(kv_pair) => {
                // if the key is already in this entry, update the value and return
                if kv_pair.0 == key {
                    let old_value = kv_pair.1;
                    kv_pair.1 = value;
                    return Some(old_value);
                }

                // transform the entry into a list entry, and make sure the key-value pairs
                // are sorted by key
                let mut pairs = vec![*kv_pair, (key, value)];
                pairs.sort_by(|a, b| cmp_digests(&a.0, &b.0));

                *self = StoreEntry::List(pairs);
                None
            }
            StoreEntry::List(pairs) => {
                match pairs.binary_search_by(|kv_pair| cmp_digests(&kv_pair.0, &key)) {
                    Ok(pos) => {
                        let old_value = pairs[pos].1;
                        pairs[pos].1 = value;
                        Some(old_value)
                    }
                    Err(pos) => {
                        pairs.insert(pos, (key, value));
                        None
                    }
                }
            }
        }
    }

    /// Removes the key-value pair with the specified key from this entry, and returns the value
    /// of the removed pair. If the entry did not contain a key-value pair for the specified key,
    /// None is returned.
    ///
    /// If the last last key-value pair was removed from the entry, the second tuple value will
    /// be set to true.
    pub fn remove(&mut self, key: &RpoDigest) -> (Option<Word>, bool) {
        match self {
            StoreEntry::Single(kv_pair) => {
                if kv_pair.0 == *key {
                    (Some(kv_pair.1), true)
                } else {
                    (None, false)
                }
            }
            StoreEntry::List(kv_pairs) => {
                match kv_pairs.binary_search_by(|kv_pair| cmp_digests(&kv_pair.0, key)) {
                    Ok(pos) => {
                        let kv_pair = kv_pairs.remove(pos);
                        if kv_pairs.len() == 1 {
                            *self = StoreEntry::Single(kv_pairs[0]);
                        }
                        (Some(kv_pair.1), false)
                    }
                    Err(_) => (None, false),
                }
            }
        }
    }
}

/// A custom iterator over key-value pairs of a [StoreEntry].
///
/// For a `SingleEntry` this returns only one value, but for `ListEntry`, this iterates over the
/// entire list of key-value pairs.
pub struct EntryIterator<'a> {
    entry: &'a StoreEntry,
    pos: usize,
}

impl<'a> Iterator for EntryIterator<'a> {
    type Item = &'a (RpoDigest, Word);

    fn next(&mut self) -> Option<Self::Item> {
        match self.entry {
            StoreEntry::Single(kv_pair) => {
                if self.pos == 0 {
                    self.pos = 1;
                    Some(kv_pair)
                } else {
                    None
                }
            }
            StoreEntry::List(kv_pairs) => {
                if self.pos >= kv_pairs.len() {
                    None
                } else {
                    let kv_pair = &kv_pairs[self.pos];
                    self.pos += 1;
                    Some(kv_pair)
                }
            }
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Compares two digests element-by-element using their integer representations starting with the
/// most significant element.
fn cmp_digests(d1: &RpoDigest, d2: &RpoDigest) -> Ordering {
    let d1 = Word::from(d1);
    let d2 = Word::from(d2);

    for (v1, v2) in d1.iter().zip(d2.iter()).rev() {
        let v1 = v1.as_int();
        let v2 = v2.as_int();
        if v1 != v2 {
            return v1.cmp(&v2);
        }
    }

    Ordering::Equal
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use super::{RpoDigest, ValueStore};
    use crate::{
        merkle::{tiered_smt::values::StoreEntry, NodeIndex},
        Felt, ONE, WORD_SIZE, ZERO,
    };

    #[test]
    fn test_insert() {
        let mut store = ValueStore::default();

        // insert the first key-value pair into the store
        let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_a = RpoDigest::from([ZERO, ONE, ONE, Felt::new(raw_a)]);
        let value_a = [ONE; WORD_SIZE];

        assert!(store.insert(key_a, value_a).is_none());
        assert_eq!(store.values.len(), 1);

        let entry = store.values.get(&raw_a).unwrap();
        let expected_entry = StoreEntry::Single((key_a, value_a));
        assert_eq!(entry, &expected_entry);

        // insert a key-value pair with a different key into the store; since the keys are
        // different, another entry is added to the values map
        let raw_b = 0b_11111110_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
        let value_b = [ONE, ZERO, ONE, ZERO];

        assert!(store.insert(key_b, value_b).is_none());
        assert_eq!(store.values.len(), 2);

        let entry1 = store.values.get(&raw_a).unwrap();
        let expected_entry1 = StoreEntry::Single((key_a, value_a));
        assert_eq!(entry1, &expected_entry1);

        let entry2 = store.values.get(&raw_b).unwrap();
        let expected_entry2 = StoreEntry::Single((key_b, value_b));
        assert_eq!(entry2, &expected_entry2);

        // insert a key-value pair with the same 64-bit key prefix as the first key; this should
        // transform the first entry into a List entry
        let key_c = RpoDigest::from([ONE, ONE, ZERO, Felt::new(raw_a)]);
        let value_c = [ONE, ONE, ZERO, ZERO];

        assert!(store.insert(key_c, value_c).is_none());
        assert_eq!(store.values.len(), 2);

        let entry1 = store.values.get(&raw_a).unwrap();
        let expected_entry1 = StoreEntry::List(vec![(key_c, value_c), (key_a, value_a)]);
        assert_eq!(entry1, &expected_entry1);

        let entry2 = store.values.get(&raw_b).unwrap();
        let expected_entry2 = StoreEntry::Single((key_b, value_b));
        assert_eq!(entry2, &expected_entry2);

        // replace values for keys a and b
        let value_a2 = [ONE, ONE, ONE, ZERO];
        let value_b2 = [ZERO, ZERO, ZERO, ONE];

        assert_eq!(store.insert(key_a, value_a2), Some(value_a));
        assert_eq!(store.values.len(), 2);

        assert_eq!(store.insert(key_b, value_b2), Some(value_b));
        assert_eq!(store.values.len(), 2);

        let entry1 = store.values.get(&raw_a).unwrap();
        let expected_entry1 = StoreEntry::List(vec![(key_c, value_c), (key_a, value_a2)]);
        assert_eq!(entry1, &expected_entry1);

        let entry2 = store.values.get(&raw_b).unwrap();
        let expected_entry2 = StoreEntry::Single((key_b, value_b2));
        assert_eq!(entry2, &expected_entry2);

        // insert one more key-value pair with the same 64-bit key-prefix as the first key
        let key_d = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
        let value_d = [ZERO, ONE, ZERO, ZERO];

        assert!(store.insert(key_d, value_d).is_none());
        assert_eq!(store.values.len(), 2);

        let entry1 = store.values.get(&raw_a).unwrap();
        let expected_entry1 =
            StoreEntry::List(vec![(key_c, value_c), (key_a, value_a2), (key_d, value_d)]);
        assert_eq!(entry1, &expected_entry1);

        let entry2 = store.values.get(&raw_b).unwrap();
        let expected_entry2 = StoreEntry::Single((key_b, value_b2));
        assert_eq!(entry2, &expected_entry2);
    }

    #[test]
    fn test_remove() {
        // populate the value store
        let mut store = ValueStore::default();

        let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_a = RpoDigest::from([ZERO, ONE, ONE, Felt::new(raw_a)]);
        let value_a = [ONE; WORD_SIZE];
        store.insert(key_a, value_a);

        let raw_b = 0b_11111110_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
        let value_b = [ONE, ZERO, ONE, ZERO];
        store.insert(key_b, value_b);

        let key_c = RpoDigest::from([ONE, ONE, ZERO, Felt::new(raw_a)]);
        let value_c = [ONE, ONE, ZERO, ZERO];
        store.insert(key_c, value_c);

        let key_d = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
        let value_d = [ZERO, ONE, ZERO, ZERO];
        store.insert(key_d, value_d);

        assert_eq!(store.values.len(), 2);

        let entry1 = store.values.get(&raw_a).unwrap();
        let expected_entry1 =
            StoreEntry::List(vec![(key_c, value_c), (key_a, value_a), (key_d, value_d)]);
        assert_eq!(entry1, &expected_entry1);

        let entry2 = store.values.get(&raw_b).unwrap();
        let expected_entry2 = StoreEntry::Single((key_b, value_b));
        assert_eq!(entry2, &expected_entry2);

        // remove non-existent keys
        let key_e = RpoDigest::from([ZERO, ZERO, ONE, Felt::new(raw_a)]);
        assert!(store.remove(&key_e).is_none());

        let raw_f = 0b_11111110_11111111_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_f = RpoDigest::from([ZERO, ZERO, ONE, Felt::new(raw_f)]);
        assert!(store.remove(&key_f).is_none());

        // remove keys from the list entry
        assert_eq!(store.remove(&key_c).unwrap(), value_c);
        let entry1 = store.values.get(&raw_a).unwrap();
        let expected_entry1 = StoreEntry::List(vec![(key_a, value_a), (key_d, value_d)]);
        assert_eq!(entry1, &expected_entry1);

        assert_eq!(store.remove(&key_a).unwrap(), value_a);
        let entry1 = store.values.get(&raw_a).unwrap();
        let expected_entry1 = StoreEntry::Single((key_d, value_d));
        assert_eq!(entry1, &expected_entry1);

        assert_eq!(store.remove(&key_d).unwrap(), value_d);
        assert!(store.values.get(&raw_a).is_none());
        assert_eq!(store.values.len(), 1);

        // remove a key from a single entry
        assert_eq!(store.remove(&key_b).unwrap(), value_b);
        assert!(store.values.get(&raw_b).is_none());
        assert_eq!(store.values.len(), 0);
    }

    #[test]
    fn test_range() {
        // populate the value store
        let mut store = ValueStore::default();

        let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_a = RpoDigest::from([ZERO, ONE, ONE, Felt::new(raw_a)]);
        let value_a = [ONE; WORD_SIZE];
        store.insert(key_a, value_a);

        let raw_b = 0b_11111110_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
        let value_b = [ONE, ZERO, ONE, ZERO];
        store.insert(key_b, value_b);

        let key_c = RpoDigest::from([ONE, ONE, ZERO, Felt::new(raw_a)]);
        let value_c = [ONE, ONE, ZERO, ZERO];
        store.insert(key_c, value_c);

        let key_d = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
        let value_d = [ZERO, ONE, ZERO, ZERO];
        store.insert(key_d, value_d);

        let raw_e = 0b_10101000_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_e = RpoDigest::from([ZERO, ONE, ONE, Felt::new(raw_e)]);
        let value_e = [ZERO, ZERO, ZERO, ONE];
        store.insert(key_e, value_e);

        // check the entire range
        let mut iter = store.range(..u64::MAX);
        assert_eq!(iter.next(), Some(&(key_e, value_e)));
        assert_eq!(iter.next(), Some(&(key_c, value_c)));
        assert_eq!(iter.next(), Some(&(key_a, value_a)));
        assert_eq!(iter.next(), Some(&(key_d, value_d)));
        assert_eq!(iter.next(), Some(&(key_b, value_b)));
        assert_eq!(iter.next(), None);

        // check all but e
        let mut iter = store.range(raw_a..u64::MAX);
        assert_eq!(iter.next(), Some(&(key_c, value_c)));
        assert_eq!(iter.next(), Some(&(key_a, value_a)));
        assert_eq!(iter.next(), Some(&(key_d, value_d)));
        assert_eq!(iter.next(), Some(&(key_b, value_b)));
        assert_eq!(iter.next(), None);

        // check all but e and b
        let mut iter = store.range(raw_a..raw_b);
        assert_eq!(iter.next(), Some(&(key_c, value_c)));
        assert_eq!(iter.next(), Some(&(key_a, value_a)));
        assert_eq!(iter.next(), Some(&(key_d, value_d)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_get_lone_sibling() {
        // populate the value store
        let mut store = ValueStore::default();

        let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_a = RpoDigest::from([ZERO, ONE, ONE, Felt::new(raw_a)]);
        let value_a = [ONE; WORD_SIZE];
        store.insert(key_a, value_a);

        let raw_b = 0b_11111111_11111111_00011111_11111111_10010110_10010011_11100000_00000000_u64;
        let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
        let value_b = [ONE, ZERO, ONE, ZERO];
        store.insert(key_b, value_b);

        // check sibling node for `a`
        let index = NodeIndex::make(32, 0b_10101010_10101010_00011111_11111110);
        let parent_index = NodeIndex::make(16, 0b_10101010_10101010);
        assert_eq!(store.get_lone_sibling(index), Some((&key_a, &value_a, parent_index)));

        // check sibling node for `b`
        let index = NodeIndex::make(32, 0b_11111111_11111111_00011111_11111111);
        let parent_index = NodeIndex::make(16, 0b_11111111_11111111);
        assert_eq!(store.get_lone_sibling(index), Some((&key_b, &value_b, parent_index)));

        // check some other sibling for some other index
        let index = NodeIndex::make(32, 0b_11101010_10101010);
        assert_eq!(store.get_lone_sibling(index), None);
    }
}
