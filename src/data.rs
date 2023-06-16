use super::utils::{
    collections::{btree_map::IntoIter, BTreeMap, BTreeSet},
    Box,
};
use core::{
    cell::RefCell,
    iter::{Chain, Filter},
};

// KEY-VALUE MAP TRAIT
// ================================================================================================
/// A trait that defines the interface for a key-value map.
pub trait KvMap<K, V> {
    fn get(&self, key: &K) -> Option<&V>;
    fn contains_key(&self, key: &K) -> bool;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn iter(&self) -> Box<dyn Iterator<Item = (&K, &V)> + '_>;
    fn insert(&mut self, key: K, value: V) -> Option<V>;
}

// RECORDING MAP
// ================================================================================================

/// A [RecordingMap] that records read requests to the underlying key-value map.
/// The data recorder is used to generate a proof for read requests.
///
/// The [RecordingMap] is composed of three parts:
/// - `data`: which contains the initial key-value pairs from the underlying data set.
/// - `delta`: which contains key-value pairs which have been created after instantiation.
/// - `updated_keys`: which tracks keys from `data` which have been updated in `delta`.
/// - `trace`: which contains the keys from the initial data set (`data`) that are read.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecordingMap<K, V> {
    data: BTreeMap<K, V>,
    delta: BTreeMap<K, V>,
    updated_keys: BTreeSet<K>,
    trace: RefCell<BTreeSet<K>>,
}

impl<K: Ord + Clone, V: Clone> RecordingMap<K, V> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [RecordingMap] instance initialized with the provided key-value pairs.
    /// ([BTreeMap]).
    pub fn new(init: impl IntoIterator<Item = (K, V)>) -> Self {
        RecordingMap {
            data: init.into_iter().collect(),
            delta: BTreeMap::new(),
            updated_keys: BTreeSet::new(),
            trace: RefCell::new(BTreeSet::new()),
        }
    }

    // FINALIZER
    // --------------------------------------------------------------------------------------------
    /// Consumes the [DataRecorder] and returns a [BTreeMap] containing the key-value pairs from
    /// the initial data set that were read during recording.
    pub fn into_proof(self) -> BTreeMap<K, V> {
        self.data
            .into_iter()
            .filter(|(k, _)| self.trace.borrow().contains(k))
            .collect::<BTreeMap<_, _>>()
    }
}

impl<K: Ord + Clone, V: Clone> KvMap<K, V> for RecordingMap<K, V> {
    // ACCESSORS
    // --------------------------------------------------------------------------------------------
    /// Returns a reference to the value associated with the given key if the value exists. If the
    /// key is part of the initial data set, the key access is recorded.
    fn get(&self, key: &K) -> Option<&V> {
        if let Some(value) = self.delta.get(key) {
            return Some(value);
        }

        match self.data.get(key) {
            None => None,
            Some(value) => {
                self.trace.borrow_mut().insert(key.clone());
                Some(value)
            }
        }
    }

    /// Returns a boolean to indicate whether the given key exists in the data set. If the key is
    /// part of the initial data set, the key access is recorded.
    fn contains_key(&self, key: &K) -> bool {
        if self.delta.contains_key(key) {
            return true;
        }

        match self.data.contains_key(key) {
            true => {
                self.trace.borrow_mut().insert(key.clone());
                true
            }
            false => false,
        }
    }

    /// Returns the number of key-value pairs in the data set.
    fn len(&self) -> usize {
        self.data.len() + self.delta.len() - self.updated_keys.len()
    }

    /// Returns an iterator over the key-value pairs in the data set.
    fn iter(&self) -> Box<dyn Iterator<Item = (&K, &V)> + '_> {
        Box::new(
            self.data
                .iter()
                .filter(|(k, _)| !self.updated_keys.contains(k))
                .chain(self.delta.iter()),
        )
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a key-value pair into the data set. If the key already exists in the data set, the
    /// value is updated and the old value is returned.
    fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some(value) = self.delta.insert(key.clone(), value) {
            return Some(value);
        }

        match self.data.get(&key) {
            None => None,
            Some(value) => {
                self.trace.borrow_mut().insert(key.clone());
                self.updated_keys.insert(key);
                Some(value.clone())
            }
        }
    }
}

// RECORDING MAP TRAIT IMPLS
// ================================================================================================

impl<K: Clone + Ord, V: Clone> Extend<(K, V)> for RecordingMap<K, V> {
    fn extend<T: IntoIterator<Item = (K, V)>>(&mut self, iter: T) {
        iter.into_iter().for_each(move |(k, v)| {
            self.insert(k, v);
        });
    }
}

impl<K: Ord + Clone, V: Clone> Default for RecordingMap<K, V> {
    fn default() -> Self {
        RecordingMap::new(BTreeMap::new())
    }
}

impl<K: Ord + 'static, V> IntoIterator for RecordingMap<K, V> {
    type Item = (K, V);
    type IntoIter =
        Chain<Filter<IntoIter<K, V>, Box<dyn FnMut(&Self::Item) -> bool>>, IntoIter<K, V>>;

    fn into_iter(self) -> Self::IntoIter {
        #[allow(clippy::type_complexity)]
        let filter_updated: Box<dyn FnMut(&Self::Item) -> bool> =
            Box::new(move |(k, _)| !self.updated_keys.contains(k));
        let data_iter = self.data.into_iter().filter(filter_updated);
        let updates_iter = self.delta.into_iter();

        data_iter.chain(updates_iter)
    }
}

// BTREE MAP `KvMap` IMPLEMENTATION
// ================================================================================================
impl<K: Ord, V> KvMap<K, V> for BTreeMap<K, V> {
    fn get(&self, key: &K) -> Option<&V> {
        self.get(key)
    }

    fn contains_key(&self, key: &K) -> bool {
        self.contains_key(key)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (&K, &V)> + '_> {
        Box::new(self.iter())
    }

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.insert(key, value)
    }
}

// TESTS
// ================================================================================================
#[cfg(test)]
mod test_recorder {
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
        let proof = map.into_proof();

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
        let proof = map.into_proof();

        // check that the proof contains the expected values
        for (key, _) in ITEMS.iter() {
            match get_items.contains(key) {
                true => assert_eq!(proof.contains_key(key), true),
                false => assert_eq!(proof.contains_key(key), false),
            }
        }
    }

    #[test]
    fn test_len() {
        // instantiate a recording map
        let mut map = RecordingMap::new(ITEMS.to_vec());
        // length of the map should be equal to the number of items
        assert_eq!(map.len(), ITEMS.len());

        // inserting entry with key that already exists should not change the length
        map.insert(4, 5);
        assert_eq!(map.len(), ITEMS.len());

        // inserting entry with new key should increase the length
        map.insert(5, 5);
        assert_eq!(map.len(), ITEMS.len() + 1);

        // get some items so that they are saved in the trace
        let get_items = [0, 1, 2];
        for key in get_items.iter() {
            map.contains_key(key);
        }

        // Note: The length reported by the proof will be different to the length originally
        // reported by the map.
        let proof = map.into_proof();

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
}
