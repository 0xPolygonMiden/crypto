use super::{collections::ApplyDiff, diff::Diff};
use core::cell::RefCell;
use winter_utils::{
    collections::{btree_map::IntoIter, BTreeMap, BTreeSet},
    Box,
};

// KEY-VALUE MAP TRAIT
// ================================================================================================

/// A trait that defines the interface for a key-value map.
pub trait KvMap<K: Ord + Clone, V: Clone>:
    Extend<(K, V)> + FromIterator<(K, V)> + IntoIterator<Item = (K, V)>
{
    fn get(&self, key: &K) -> Option<&V>;
    fn contains_key(&self, key: &K) -> bool;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn insert(&mut self, key: K, value: V) -> Option<V>;
    fn remove(&mut self, key: &K) -> Option<V>;

    fn iter(&self) -> Box<dyn Iterator<Item = (&K, &V)> + '_>;
}

// BTREE MAP `KvMap` IMPLEMENTATION
// ================================================================================================

impl<K: Ord + Clone, V: Clone> KvMap<K, V> for BTreeMap<K, V> {
    fn get(&self, key: &K) -> Option<&V> {
        self.get(key)
    }

    fn contains_key(&self, key: &K) -> bool {
        self.contains_key(key)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.insert(key, value)
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        self.remove(key)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (&K, &V)> + '_> {
        Box::new(self.iter())
    }
}

// RECORDING MAP
// ================================================================================================

/// A [RecordingMap] that records read requests to the underlying key-value map.
///
/// The data recorder is used to generate a proof for read requests.
///
/// The [RecordingMap] is composed of three parts:
/// - `data`: which contains the current set of key-value pairs in the map.
/// - `updates`: which tracks keys for which values have been changed since the map was
///    instantiated. updates include both insertions, removals and updates of values under existing
///    keys.
/// - `trace`: which contains the key-value pairs from the original data which have been accesses
///   since the map was instantiated.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct RecordingMap<K, V> {
    data: BTreeMap<K, V>,
    updates: BTreeSet<K>,
    trace: RefCell<BTreeMap<K, V>>,
}

impl<K: Ord + Clone, V: Clone> RecordingMap<K, V> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [RecordingMap] instance initialized with the provided key-value pairs.
    /// ([BTreeMap]).
    pub fn new(init: impl IntoIterator<Item = (K, V)>) -> Self {
        RecordingMap {
            data: init.into_iter().collect(),
            updates: BTreeSet::new(),
            trace: RefCell::new(BTreeMap::new()),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn inner(&self) -> &BTreeMap<K, V> {
        &self.data
    }

    // FINALIZER
    // --------------------------------------------------------------------------------------------

    /// Consumes the [RecordingMap] and returns a ([BTreeMap], [BTreeMap]) tuple.  The first
    /// element of the tuple is a map that represents the state of the map at the time `.finalize()`
    /// is called.  The second element contains the key-value pairs from the initial data set that
    /// were read during recording.
    pub fn finalize(self) -> (BTreeMap<K, V>, BTreeMap<K, V>) {
        (self.data, self.trace.take())
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    #[cfg(test)]
    pub fn trace_len(&self) -> usize {
        self.trace.borrow().len()
    }

    #[cfg(test)]
    pub fn updates_len(&self) -> usize {
        self.updates.len()
    }
}

impl<K: Ord + Clone, V: Clone> KvMap<K, V> for RecordingMap<K, V> {
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the value associated with the given key if the value exists.
    ///
    /// If the key is part of the initial data set, the key access is recorded.
    fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key).map(|value| {
            if !self.updates.contains(key) {
                self.trace.borrow_mut().insert(key.clone(), value.clone());
            }
            value
        })
    }

    /// Returns a boolean to indicate whether the given key exists in the data set.
    ///
    /// If the key is part of the initial data set, the key access is recorded.
    fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Returns the number of key-value pairs in the data set.
    fn len(&self) -> usize {
        self.data.len()
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a key-value pair into the data set.
    ///
    /// If the key already exists in the data set, the value is updated and the old value is
    /// returned.
    fn insert(&mut self, key: K, value: V) -> Option<V> {
        let new_update = self.updates.insert(key.clone());
        self.data.insert(key.clone(), value).map(|old_value| {
            if new_update {
                self.trace.borrow_mut().insert(key, old_value.clone());
            }
            old_value
        })
    }

    /// Removes a key-value pair from the data set.
    ///
    /// If the key exists in the data set, the old value is returned.
    fn remove(&mut self, key: &K) -> Option<V> {
        self.data.remove(key).map(|old_value| {
            let new_update = self.updates.insert(key.clone());
            if new_update {
                self.trace.borrow_mut().insert(key.clone(), old_value.clone());
            }
            old_value
        })
    }

    // ITERATION
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the key-value pairs in the data set.
    fn iter(&self) -> Box<dyn Iterator<Item = (&K, &V)> + '_> {
        Box::new(self.data.iter())
    }
}

impl<K: Clone + Ord, V: Clone> Extend<(K, V)> for RecordingMap<K, V> {
    fn extend<T: IntoIterator<Item = (K, V)>>(&mut self, iter: T) {
        iter.into_iter().for_each(move |(k, v)| {
            self.insert(k, v);
        });
    }
}

impl<K: Clone + Ord, V: Clone> FromIterator<(K, V)> for RecordingMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl<K: Clone + Ord, V: Clone> IntoIterator for RecordingMap<K, V> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

// KV MAP DIFF
// ================================================================================================
/// [KvMapDiff] stores the difference between two key-value maps.
///
/// The [KvMapDiff] is composed of two parts:
/// - `updates` - a map of key-value pairs that were updated in the second map compared to the
///               first map. This includes new key-value pairs.
/// - `removed` - a set of keys that were removed from the second map compared to the first map.
#[derive(Debug, Clone)]
pub struct KvMapDiff<K, V> {
    pub updated: BTreeMap<K, V>,
    pub removed: BTreeSet<K>,
}

impl<K, V> KvMapDiff<K, V> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new [KvMapDiff] instance.
    pub fn new() -> Self {
        KvMapDiff {
            updated: BTreeMap::new(),
            removed: BTreeSet::new(),
        }
    }
}

impl<K, V> Default for KvMapDiff<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord + Clone, V: Clone + PartialEq, T: KvMap<K, V>> Diff<K, V> for T {
    type DiffType = KvMapDiff<K, V>;

    fn diff(&self, other: &T) -> Self::DiffType {
        let mut diff = KvMapDiff::default();
        for (k, v) in self.iter() {
            if let Some(other_value) = other.get(k) {
                if v != other_value {
                    diff.updated.insert(k.clone(), other_value.clone());
                }
            } else {
                diff.removed.insert(k.clone());
            }
        }
        for (k, v) in other.iter() {
            if self.get(k).is_none() {
                diff.updated.insert(k.clone(), v.clone());
            }
        }
        diff
    }
}

impl<K: Ord + Clone, V: Clone, T: KvMap<K, V>> ApplyDiff<K, V> for T {
    type DiffType = KvMapDiff<K, V>;

    fn apply(&mut self, diff: Self::DiffType) {
        for (k, v) in diff.updated {
            self.insert(k, v);
        }
        for k in diff.removed {
            self.remove(&k);
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const ITEMS: [(u64, u64); 5] = [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)];

    #[test]
    fn test_get_item() {
        // instantiate a recording map
        let map = RecordingMap::new(ITEMS.to_vec());

        // get a few items
        let get_items = [0, 1, 2];
        for key in get_items.iter() {
            map.get(key);
        }

        // convert the map into a proof
        let (_, proof) = map.finalize();

        // check that the proof contains the expected values
        for (key, value) in ITEMS.iter() {
            match get_items.contains(key) {
                true => assert_eq!(proof.get(key), Some(value)),
                false => assert_eq!(proof.get(key), None),
            }
        }
    }

    #[test]
    fn test_contains_key() {
        // instantiate a recording map
        let map = RecordingMap::new(ITEMS.to_vec());

        // check if the map contains a few items
        let get_items = [0, 1, 2];
        for key in get_items.iter() {
            map.contains_key(key);
        }

        // convert the map into a proof
        let (_, proof) = map.finalize();

        // check that the proof contains the expected values
        for (key, _) in ITEMS.iter() {
            match get_items.contains(key) {
                true => assert!(proof.contains_key(key)),
                false => assert!(!proof.contains_key(key)),
            }
        }
    }

    #[test]
    fn test_len() {
        // instantiate a recording map
        let mut map = RecordingMap::new(ITEMS.to_vec());
        // length of the map should be equal to the number of items
        assert_eq!(map.len(), ITEMS.len());

        // inserting entry with key that already exists should not change the length, but it does
        // add entries to the trace and update sets
        map.insert(4, 5);
        assert_eq!(map.len(), ITEMS.len());
        assert_eq!(map.trace_len(), 1);
        assert_eq!(map.updates_len(), 1);

        // inserting entry with new key should increase the length; it should also record the key
        // as an updated key, but the trace length does not change since old values were not touched
        map.insert(5, 5);
        assert_eq!(map.len(), ITEMS.len() + 1);
        assert_eq!(map.trace_len(), 1);
        assert_eq!(map.updates_len(), 2);

        // get some items so that they are saved in the trace; this should record original items
        // in the trace, but should not affect the set of updates
        let get_items = [0, 1, 2];
        for key in get_items.iter() {
            map.contains_key(key);
        }
        assert_eq!(map.trace_len(), 4);
        assert_eq!(map.updates_len(), 2);

        // read the same items again, this should not have any effect on either length, trace, or
        // the set of updates
        let get_items = [0, 1, 2];
        for key in get_items.iter() {
            map.contains_key(key);
        }
        assert_eq!(map.trace_len(), 4);
        assert_eq!(map.updates_len(), 2);

        // read a newly inserted item; this should not affect either length, trace, or the set of
        // updates
        let _val = map.get(&5).unwrap();
        assert_eq!(map.trace_len(), 4);
        assert_eq!(map.updates_len(), 2);

        // update a newly inserted item; this should not affect either length, trace, or the set
        // of updates
        map.insert(5, 11);
        assert_eq!(map.trace_len(), 4);
        assert_eq!(map.updates_len(), 2);

        // Note: The length reported by the proof will be different to the length originally
        // reported by the map.
        let (_, proof) = map.finalize();

        // length of the proof should be equal to get_items + 1. The extra item is the original
        // value at key = 4u64
        assert_eq!(proof.len(), get_items.len() + 1);
    }

    #[test]
    fn test_iter() {
        let mut map = RecordingMap::new(ITEMS.to_vec());
        assert!(map.iter().all(|(x, y)| ITEMS.contains(&(*x, *y))));

        // when inserting entry with key that already exists the iterator should return the new value
        let new_value = 5;
        map.insert(4, new_value);
        assert_eq!(map.iter().count(), ITEMS.len());
        assert!(map.iter().all(|(x, y)| if x == &4 {
            y == &new_value
        } else {
            ITEMS.contains(&(*x, *y))
        }));
    }

    #[test]
    fn test_is_empty() {
        // instantiate an empty recording map
        let empty_map: RecordingMap<u64, u64> = RecordingMap::default();
        assert!(empty_map.is_empty());

        // instantiate a non-empty recording map
        let map = RecordingMap::new(ITEMS.to_vec());
        assert!(!map.is_empty());
    }

    #[test]
    fn test_remove() {
        let mut map = RecordingMap::new(ITEMS.to_vec());

        // remove an item that exists
        let key = 0;
        let value = map.remove(&key).unwrap();
        assert_eq!(value, ITEMS[0].1);
        assert_eq!(map.len(), ITEMS.len() - 1);
        assert_eq!(map.trace_len(), 1);
        assert_eq!(map.updates_len(), 1);

        // add the item back and then remove it again
        let key = 0;
        let value = 0;
        map.insert(key, value);
        let value = map.remove(&key).unwrap();
        assert_eq!(value, 0);
        assert_eq!(map.len(), ITEMS.len() - 1);
        assert_eq!(map.trace_len(), 1);
        assert_eq!(map.updates_len(), 1);

        // remove an item that does not exist
        let key = 100;
        let value = map.remove(&key);
        assert_eq!(value, None);
        assert_eq!(map.len(), ITEMS.len() - 1);
        assert_eq!(map.trace_len(), 1);
        assert_eq!(map.updates_len(), 1);

        // insert a new item and then remove it
        let key = 100;
        let value = 100;
        map.insert(key, value);
        let value = map.remove(&key).unwrap();
        assert_eq!(value, 100);
        assert_eq!(map.len(), ITEMS.len() - 1);
        assert_eq!(map.trace_len(), 1);
        assert_eq!(map.updates_len(), 2);

        // convert the map into a proof
        let (_, proof) = map.finalize();

        // check that the proof contains the expected values
        for (key, value) in ITEMS.iter() {
            match key {
                0 => assert_eq!(proof.get(key), Some(value)),
                _ => assert_eq!(proof.get(key), None),
            }
        }
    }

    #[test]
    fn test_kv_map_diff() {
        let mut initial_state = ITEMS.into_iter().collect::<BTreeMap<_, _>>();
        let mut map = RecordingMap::new(initial_state.clone());

        // remove an item that exists
        let key = 0;
        let _value = map.remove(&key).unwrap();

        // add a new item
        let key = 100;
        let value = 100;
        map.insert(key, value);

        // update an existing item
        let key = 1;
        let value = 100;
        map.insert(key, value);

        // compute a diff
        let diff = initial_state.diff(map.inner());
        assert!(diff.updated.len() == 2);
        assert!(diff.updated.iter().all(|(k, v)| [(100, 100), (1, 100)].contains(&(*k, *v))));
        assert!(diff.removed.len() == 1);
        assert!(diff.removed.first() == Some(&0));

        // apply the diff to the initial state and assert the contents are the same as the map
        initial_state.apply(diff);
        assert!(initial_state.iter().eq(map.iter()));
    }
}
