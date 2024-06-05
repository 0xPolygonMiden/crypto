use super::{Felt, LeafIndex, NodeIndex, Rpo256, RpoDigest, Smt, SmtLeaf, EMPTY_WORD, SMT_DEPTH};
use crate::{
    merkle::{EmptySubtreeRoots, MerkleStore},
    utils::{Deserializable, Serializable},
    Word, ONE, WORD_SIZE,
};
use alloc::vec::Vec;

// SMT
// --------------------------------------------------------------------------------------------

/// This test checks that inserting twice at the same key functions as expected. The test covers
/// only the case where the key is alone in its leaf
#[test]
fn test_smt_insert_at_same_key() {
    let mut smt = Smt::default();
    let mut store: MerkleStore = MerkleStore::default();

    assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));

    let key_1: RpoDigest = {
        let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

        RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)])
    };
    let key_1_index: NodeIndex = LeafIndex::<SMT_DEPTH>::from(key_1).into();

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [ONE + ONE; WORD_SIZE];

    // Insert value 1 and ensure root is as expected
    {
        let leaf_node = build_empty_or_single_leaf_node(key_1, value_1);
        let tree_root = store.set_node(smt.root(), key_1_index, leaf_node).unwrap().root;

        let old_value_1 = smt.insert(key_1, value_1);
        assert_eq!(old_value_1, EMPTY_WORD);

        assert_eq!(smt.root(), tree_root);
    }

    // Insert value 2 and ensure root is as expected
    {
        let leaf_node = build_empty_or_single_leaf_node(key_1, value_2);
        let tree_root = store.set_node(smt.root(), key_1_index, leaf_node).unwrap().root;

        let old_value_2 = smt.insert(key_1, value_2);
        assert_eq!(old_value_2, value_1);

        assert_eq!(smt.root(), tree_root);
    }
}

/// This test checks that inserting twice at the same key functions as expected. The test covers
/// only the case where the leaf type is `SmtLeaf::Multiple`
#[test]
fn test_smt_insert_at_same_key_2() {
    // The most significant u64 used for both keys (to ensure they map to the same leaf)
    let key_msb: u64 = 42;

    let key_already_present: RpoDigest =
        RpoDigest::from([2_u32.into(), 2_u32.into(), 2_u32.into(), Felt::new(key_msb)]);
    let key_already_present_index: NodeIndex =
        LeafIndex::<SMT_DEPTH>::from(key_already_present).into();
    let value_already_present = [ONE + ONE + ONE; WORD_SIZE];

    let mut smt =
        Smt::with_entries(core::iter::once((key_already_present, value_already_present))).unwrap();
    let mut store: MerkleStore = {
        let mut store = MerkleStore::default();

        let leaf_node = build_empty_or_single_leaf_node(key_already_present, value_already_present);
        store
            .set_node(*EmptySubtreeRoots::entry(SMT_DEPTH, 0), key_already_present_index, leaf_node)
            .unwrap();
        store
    };

    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, Felt::new(key_msb)]);
    let key_1_index: NodeIndex = LeafIndex::<SMT_DEPTH>::from(key_1).into();

    assert_eq!(key_1_index, key_already_present_index);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [ONE + ONE; WORD_SIZE];

    // Insert value 1 and ensure root is as expected
    {
        // Note: key_1 comes first because it is smaller
        let leaf_node = build_multiple_leaf_node(&[
            (key_1, value_1),
            (key_already_present, value_already_present),
        ]);
        let tree_root = store.set_node(smt.root(), key_1_index, leaf_node).unwrap().root;

        let old_value_1 = smt.insert(key_1, value_1);
        assert_eq!(old_value_1, EMPTY_WORD);

        assert_eq!(smt.root(), tree_root);
    }

    // Insert value 2 and ensure root is as expected
    {
        let leaf_node = build_multiple_leaf_node(&[
            (key_1, value_2),
            (key_already_present, value_already_present),
        ]);
        let tree_root = store.set_node(smt.root(), key_1_index, leaf_node).unwrap().root;

        let old_value_2 = smt.insert(key_1, value_2);
        assert_eq!(old_value_2, value_1);

        assert_eq!(smt.root(), tree_root);
    }
}

/// This test ensures that the root of the tree is as expected when we add/remove 3 items at 3
/// different keys. This also tests that the merkle paths produced are as expected.
#[test]
fn test_smt_insert_and_remove_multiple_values() {
    fn insert_values_and_assert_path(
        smt: &mut Smt,
        store: &mut MerkleStore,
        key_values: &[(RpoDigest, Word)],
    ) {
        for &(key, value) in key_values {
            let key_index: NodeIndex = LeafIndex::<SMT_DEPTH>::from(key).into();

            let leaf_node = build_empty_or_single_leaf_node(key, value);
            let tree_root = store.set_node(smt.root(), key_index, leaf_node).unwrap().root;

            let _ = smt.insert(key, value);

            assert_eq!(smt.root(), tree_root);

            let expected_path = store.get_path(tree_root, key_index).unwrap();
            assert_eq!(smt.open(&key).into_parts().0, expected_path.path);
        }
    }
    let mut smt = Smt::default();
    let mut store: MerkleStore = MerkleStore::default();

    assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));

    let key_1: RpoDigest = {
        let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

        RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)])
    };

    let key_2: RpoDigest = {
        let raw = 0b_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_u64;

        RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)])
    };

    let key_3: RpoDigest = {
        let raw = 0b_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_u64;

        RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)])
    };

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [ONE + ONE; WORD_SIZE];
    let value_3 = [ONE + ONE + ONE; WORD_SIZE];

    // Insert values in the tree
    let key_values = [(key_1, value_1), (key_2, value_2), (key_3, value_3)];
    insert_values_and_assert_path(&mut smt, &mut store, &key_values);

    // Remove values from the tree
    let key_empty_values = [(key_1, EMPTY_WORD), (key_2, EMPTY_WORD), (key_3, EMPTY_WORD)];
    insert_values_and_assert_path(&mut smt, &mut store, &key_empty_values);

    let empty_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    assert_eq!(smt.root(), empty_root);

    // an empty tree should have no leaves or inner nodes
    assert!(smt.leaves.is_empty());
    assert!(smt.inner_nodes.is_empty());
}

/// This tests that inserting the empty value does indeed remove the key-value contained at the
/// leaf. We insert & remove 3 values at the same leaf to ensure that all cases are covered (empty,
/// single, multiple).
#[test]
fn test_smt_removal() {
    let mut smt = Smt::default();

    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2: RpoDigest =
        RpoDigest::from([2_u32.into(), 2_u32.into(), 2_u32.into(), Felt::new(raw)]);
    let key_3: RpoDigest =
        RpoDigest::from([3_u32.into(), 3_u32.into(), 3_u32.into(), Felt::new(raw)]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];
    let value_3: [Felt; 4] = [3_u32.into(); WORD_SIZE];

    // insert key-value 1
    {
        let old_value_1 = smt.insert(key_1, value_1);
        assert_eq!(old_value_1, EMPTY_WORD);

        assert_eq!(smt.get_leaf(&key_1), SmtLeaf::Single((key_1, value_1)));
    }

    // insert key-value 2
    {
        let old_value_2 = smt.insert(key_2, value_2);
        assert_eq!(old_value_2, EMPTY_WORD);

        assert_eq!(
            smt.get_leaf(&key_2),
            SmtLeaf::Multiple(vec![(key_1, value_1), (key_2, value_2)])
        );
    }

    // insert key-value 3
    {
        let old_value_3 = smt.insert(key_3, value_3);
        assert_eq!(old_value_3, EMPTY_WORD);

        assert_eq!(
            smt.get_leaf(&key_3),
            SmtLeaf::Multiple(vec![(key_1, value_1), (key_2, value_2), (key_3, value_3)])
        );
    }

    // remove key 3
    {
        let old_value_3 = smt.insert(key_3, EMPTY_WORD);
        assert_eq!(old_value_3, value_3);

        assert_eq!(
            smt.get_leaf(&key_3),
            SmtLeaf::Multiple(vec![(key_1, value_1), (key_2, value_2)])
        );
    }

    // remove key 2
    {
        let old_value_2 = smt.insert(key_2, EMPTY_WORD);
        assert_eq!(old_value_2, value_2);

        assert_eq!(smt.get_leaf(&key_2), SmtLeaf::Single((key_1, value_1)));
    }

    // remove key 1
    {
        let old_value_1 = smt.insert(key_1, EMPTY_WORD);
        assert_eq!(old_value_1, value_1);

        assert_eq!(smt.get_leaf(&key_1), SmtLeaf::new_empty(key_1.into()));
    }
}

/// Tests that 2 key-value pairs stored in the same leaf have the same path
#[test]
fn test_smt_path_to_keys_in_same_leaf_are_equal() {
    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2: RpoDigest =
        RpoDigest::from([2_u32.into(), 2_u32.into(), 2_u32.into(), Felt::new(raw)]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];

    let smt = Smt::with_entries([(key_1, value_1), (key_2, value_2)]).unwrap();

    assert_eq!(smt.open(&key_1), smt.open(&key_2));
}

/// Tests that an empty leaf hashes to the empty word
#[test]
fn test_empty_leaf_hash() {
    let smt = Smt::default();

    let leaf = smt.get_leaf(&RpoDigest::default());
    assert_eq!(leaf.hash(), EMPTY_WORD.into());
}

/// Tests that `get_value()` works as expected
#[test]
fn test_smt_get_value() {
    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, ONE]);
    let key_2: RpoDigest = RpoDigest::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];

    let smt = Smt::with_entries([(key_1, value_1), (key_2, value_2)]).unwrap();

    let returned_value_1 = smt.get_value(&key_1);
    let returned_value_2 = smt.get_value(&key_2);

    assert_eq!(value_1, returned_value_1);
    assert_eq!(value_2, returned_value_2);

    // Check that a key with no inserted value returns the empty word
    let key_no_value = RpoDigest::from([42_u32, 42_u32, 42_u32, 42_u32]);

    assert_eq!(EMPTY_WORD, smt.get_value(&key_no_value));
}

/// Tests that `entries()` works as expected
#[test]
fn test_smt_entries() {
    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, ONE]);
    let key_2: RpoDigest = RpoDigest::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];

    let smt = Smt::with_entries([(key_1, value_1), (key_2, value_2)]).unwrap();

    let mut entries = smt.entries();

    // Note: for simplicity, we assume the order `(k1,v1), (k2,v2)`. If a new implementation
    // switches the order, it is OK to modify the order here as well.
    assert_eq!(&(key_1, value_1), entries.next().unwrap());
    assert_eq!(&(key_2, value_2), entries.next().unwrap());
    assert!(entries.next().is_none());
}

// SMT LEAF
// --------------------------------------------------------------------------------------------

#[test]
fn test_empty_smt_leaf_serialization() {
    let empty_leaf = SmtLeaf::new_empty(LeafIndex::new_max_depth(42));

    let mut serialized = empty_leaf.to_bytes();
    // extend buffer with random bytes
    serialized.extend([1, 2, 3, 4, 5]);
    let deserialized = SmtLeaf::read_from_bytes(&serialized).unwrap();

    assert_eq!(empty_leaf, deserialized);
}

#[test]
fn test_single_smt_leaf_serialization() {
    let single_leaf = SmtLeaf::new_single(
        RpoDigest::from([10_u32, 11_u32, 12_u32, 13_u32]),
        [1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into()],
    );

    let mut serialized = single_leaf.to_bytes();
    // extend buffer with random bytes
    serialized.extend([1, 2, 3, 4, 5]);
    let deserialized = SmtLeaf::read_from_bytes(&serialized).unwrap();

    assert_eq!(single_leaf, deserialized);
}

#[test]
fn test_multiple_smt_leaf_serialization_success() {
    let multiple_leaf = SmtLeaf::new_multiple(vec![
        (
            RpoDigest::from([10_u32, 11_u32, 12_u32, 13_u32]),
            [1_u32.into(), 2_u32.into(), 3_u32.into(), 4_u32.into()],
        ),
        (
            RpoDigest::from([100_u32, 101_u32, 102_u32, 13_u32]),
            [11_u32.into(), 12_u32.into(), 13_u32.into(), 14_u32.into()],
        ),
    ])
    .unwrap();

    let mut serialized = multiple_leaf.to_bytes();
    // extend buffer with random bytes
    serialized.extend([1, 2, 3, 4, 5]);
    let deserialized = SmtLeaf::read_from_bytes(&serialized).unwrap();

    assert_eq!(multiple_leaf, deserialized);
}

// HELPERS
// --------------------------------------------------------------------------------------------

fn build_empty_or_single_leaf_node(key: RpoDigest, value: Word) -> RpoDigest {
    if value == EMPTY_WORD {
        SmtLeaf::new_empty(key.into()).hash()
    } else {
        SmtLeaf::Single((key, value)).hash()
    }
}

fn build_multiple_leaf_node(kv_pairs: &[(RpoDigest, Word)]) -> RpoDigest {
    let elements: Vec<Felt> = kv_pairs
        .iter()
        .flat_map(|(key, value)| {
            let key_elements = key.into_iter();
            let value_elements = (*value).into_iter();

            key_elements.chain(value_elements)
        })
        .collect();

    Rpo256::hash_elements(&elements)
}
