use super::*;
use crate::{
    merkle::{EmptySubtreeRoots, MerkleStore},
    ONE, WORD_SIZE,
};

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
        let leaf_node = build_single_leaf_node(key_1, value_1);
        let tree_root = store.set_node(smt.root(), key_1_index, leaf_node).unwrap().root;

        let old_value_1 = smt.insert(key_1, value_1);
        assert_eq!(old_value_1, EMPTY_WORD);

        assert_eq!(smt.root(), tree_root);
    }

    // Insert value 2 and ensure root is as expected
    {
        let leaf_node = build_single_leaf_node(key_1, value_2);
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
    let key_already_present: RpoDigest = {
        let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

        RpoDigest::from([ONE + ONE, ONE + ONE, ONE + ONE, Felt::new(raw)])
    };
    let key_already_present_index: NodeIndex =
        LeafIndex::<SMT_DEPTH>::from(key_already_present).into();
    let value_already_present = [ONE + ONE + ONE; WORD_SIZE];

    let mut smt =
        Smt::with_entries(core::iter::once((key_already_present, value_already_present))).unwrap();
    let mut store: MerkleStore = {
        let mut store = MerkleStore::default();

        let leaf_node = build_single_leaf_node(key_already_present, value_already_present);
        store
            .set_node(*EmptySubtreeRoots::entry(SMT_DEPTH, 0), key_already_present_index, leaf_node)
            .unwrap();
        store
    };

    let key_1: RpoDigest = {
        let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

        RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)])
    };
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

/// This test ensures that the root of the tree is as expected when we add 3 items at 3 different
/// keys. This also tests that the merkle paths produced are as expected.
#[test]
fn test_smt_insert_multiple_values() {
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

    let key_values = [(key_1, value_1), (key_2, value_2), (key_3, value_3)];

    for (key, value) in key_values {
        let key_index: NodeIndex = LeafIndex::<SMT_DEPTH>::from(key).into();

        let leaf_node = build_single_leaf_node(key, value);
        let tree_root = store.set_node(smt.root(), key_index, leaf_node).unwrap().root;

        let old_value = smt.insert(key, value);
        assert_eq!(old_value, EMPTY_WORD);

        assert_eq!(smt.root(), tree_root);

        let expected_path = store.get_path(tree_root, key_index).unwrap();
        assert_eq!(smt.open(&key).0, expected_path.path);
    }
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
        RpoDigest::from([2_u64.into(), 2_u64.into(), 2_u64.into(), Felt::new(raw)]);
    let key_3: RpoDigest =
        RpoDigest::from([3_u64.into(), 3_u64.into(), 3_u64.into(), Felt::new(raw)]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u64.into(); WORD_SIZE];
    let value_3: [Felt; 4] = [3_u64.into(); WORD_SIZE];

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

        assert_eq!(smt.get_leaf(&key_1), SmtLeaf::Single((key_1, EMPTY_WORD)));
    }
}

/// Tests that 2 key-value pairs stored in the same leaf have the same path
#[test]
fn test_smt_path_to_keys_in_same_leaf_are_equal() {
    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2: RpoDigest =
        RpoDigest::from([2_u64.into(), 2_u64.into(), 2_u64.into(), Felt::new(raw)]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u64.into(); WORD_SIZE];

    let smt = Smt::with_entries([(key_1, value_1), (key_2, value_2)]).unwrap();

    assert_eq!(smt.open(&key_1), smt.open(&key_2));
}

// HELPERS
// --------------------------------------------------------------------------------------------

fn build_single_leaf_node(key: RpoDigest, value: Word) -> RpoDigest {
    SmtLeaf::Single((key, value)).hash()
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
