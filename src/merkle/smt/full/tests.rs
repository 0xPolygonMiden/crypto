use alloc::vec::Vec;

use super::{Felt, LeafIndex, NodeIndex, Rpo256, RpoDigest, Smt, SmtLeaf, EMPTY_WORD, SMT_DEPTH};
use crate::{
    merkle::{
        smt::{NodeMutation, SparseMerkleTree, UnorderedMap},
        EmptySubtreeRoots, MerkleStore, MutationSet,
    },
    utils::{Deserializable, Serializable},
    Word, ONE, WORD_SIZE,
};
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

/// This tests that we can correctly calculate prospective leaves -- that is, we can construct
/// correct [`SmtLeaf`] values for a theoretical insertion on a Merkle tree without mutating or
/// cloning the tree.
#[test]
fn test_prospective_hash() {
    let mut smt = Smt::default();

    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2: RpoDigest =
        RpoDigest::from([2_u32.into(), 2_u32.into(), 2_u32.into(), Felt::new(raw)]);
    // Sort key_3 before key_1, to test non-append insertion.
    let key_3: RpoDigest =
        RpoDigest::from([0_u32.into(), 0_u32.into(), 0_u32.into(), Felt::new(raw)]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];
    let value_3: [Felt; 4] = [3_u32.into(); WORD_SIZE];

    // insert key-value 1
    {
        let prospective =
            smt.construct_prospective_leaf(smt.get_leaf(&key_1), &key_1, &value_1).hash();
        smt.insert(key_1, value_1);

        let leaf = smt.get_leaf(&key_1);
        assert_eq!(
            prospective,
            leaf.hash(),
            "prospective hash for leaf {leaf:?} did not match actual hash",
        );
    }

    // insert key-value 2
    {
        let prospective =
            smt.construct_prospective_leaf(smt.get_leaf(&key_2), &key_2, &value_2).hash();
        smt.insert(key_2, value_2);

        let leaf = smt.get_leaf(&key_2);
        assert_eq!(
            prospective,
            leaf.hash(),
            "prospective hash for leaf {leaf:?} did not match actual hash",
        );
    }

    // insert key-value 3
    {
        let prospective =
            smt.construct_prospective_leaf(smt.get_leaf(&key_3), &key_3, &value_3).hash();
        smt.insert(key_3, value_3);

        let leaf = smt.get_leaf(&key_3);
        assert_eq!(
            prospective,
            leaf.hash(),
            "prospective hash for leaf {leaf:?} did not match actual hash",
        );
    }

    // remove key 3
    {
        let old_leaf = smt.get_leaf(&key_3);
        let old_value_3 = smt.insert(key_3, EMPTY_WORD);
        assert_eq!(old_value_3, value_3);
        let prospective_leaf =
            smt.construct_prospective_leaf(smt.get_leaf(&key_3), &key_3, &old_value_3);

        assert_eq!(
            old_leaf.hash(),
            prospective_leaf.hash(),
            "removing and prospectively re-adding a leaf didn't yield the original leaf:\
            \n  original leaf:    {old_leaf:?}\
            \n  prospective leaf: {prospective_leaf:?}",
        );
    }

    // remove key 2
    {
        let old_leaf = smt.get_leaf(&key_2);
        let old_value_2 = smt.insert(key_2, EMPTY_WORD);
        assert_eq!(old_value_2, value_2);
        let prospective_leaf =
            smt.construct_prospective_leaf(smt.get_leaf(&key_2), &key_2, &old_value_2);

        assert_eq!(
            old_leaf.hash(),
            prospective_leaf.hash(),
            "removing and prospectively re-adding a leaf didn't yield the original leaf:\
            \n  original leaf:    {old_leaf:?}\
            \n  prospective leaf: {prospective_leaf:?}",
        );
    }

    // remove key 1
    {
        let old_leaf = smt.get_leaf(&key_1);
        let old_value_1 = smt.insert(key_1, EMPTY_WORD);
        assert_eq!(old_value_1, value_1);
        let prospective_leaf =
            smt.construct_prospective_leaf(smt.get_leaf(&key_1), &key_1, &old_value_1);
        assert_eq!(
            old_leaf.hash(),
            prospective_leaf.hash(),
            "removing and prospectively re-adding a leaf didn't yield the original leaf:\
            \n  original leaf:    {old_leaf:?}\
            \n  prospective leaf: {prospective_leaf:?}",
        );
    }
}

/// This tests that we can perform prospective changes correctly.
#[test]
fn test_prospective_insertion() {
    let mut smt = Smt::default();

    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2: RpoDigest =
        RpoDigest::from([2_u32.into(), 2_u32.into(), 2_u32.into(), Felt::new(raw)]);
    // Sort key_3 before key_1, to test non-append insertion.
    let key_3: RpoDigest =
        RpoDigest::from([0_u32.into(), 0_u32.into(), 0_u32.into(), Felt::new(raw)]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];
    let value_3: [Felt; 4] = [3_u32.into(); WORD_SIZE];

    let root_empty = smt.root();

    let root_1 = {
        smt.insert(key_1, value_1);
        smt.root()
    };

    let root_2 = {
        smt.insert(key_2, value_2);
        smt.root()
    };

    let root_3 = {
        smt.insert(key_3, value_3);
        smt.root()
    };

    // Test incremental updates.

    let mut smt = Smt::default();

    let mutations = smt.compute_mutations(vec![(key_1, value_1)]);
    assert_eq!(mutations.root(), root_1, "prospective root 1 did not match actual root 1");
    let revert = apply_mutations(&mut smt, mutations);
    assert_eq!(smt.root(), root_1, "mutations before and after apply did not match");
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), root_empty, "reverse mutations new root did not match");
    assert_eq!(
        revert.new_pairs,
        UnorderedMap::from_iter([(key_1, EMPTY_WORD)]),
        "reverse mutations pairs did not match"
    );
    assert_eq!(
        revert.node_mutations,
        smt.inner_nodes.keys().map(|key| (*key, NodeMutation::Removal)).collect(),
        "reverse mutations inner nodes did not match"
    );

    let mutations = smt.compute_mutations(vec![(key_2, value_2)]);
    assert_eq!(mutations.root(), root_2, "prospective root 2 did not match actual root 2");
    let mutations =
        smt.compute_mutations(vec![(key_3, EMPTY_WORD), (key_2, value_2), (key_3, value_3)]);
    assert_eq!(mutations.root(), root_3, "mutations before and after apply did not match");
    let old_root = smt.root();
    let revert = apply_mutations(&mut smt, mutations);
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), old_root, "reverse mutations new root did not match");
    assert_eq!(
        revert.new_pairs,
        UnorderedMap::from_iter([(key_2, EMPTY_WORD), (key_3, EMPTY_WORD)]),
        "reverse mutations pairs did not match"
    );

    // Edge case: multiple values at the same key, where a later pair restores the original value.
    let mutations = smt.compute_mutations(vec![(key_3, EMPTY_WORD), (key_3, value_3)]);
    assert_eq!(mutations.root(), root_3);
    let old_root = smt.root();
    let revert = apply_mutations(&mut smt, mutations);
    assert_eq!(smt.root(), root_3);
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), old_root, "reverse mutations new root did not match");
    assert_eq!(
        revert.new_pairs,
        UnorderedMap::from_iter([(key_3, value_3)]),
        "reverse mutations pairs did not match"
    );

    // Test batch updates, and that the order doesn't matter.
    let pairs =
        vec![(key_3, value_2), (key_2, EMPTY_WORD), (key_1, EMPTY_WORD), (key_3, EMPTY_WORD)];
    let mutations = smt.compute_mutations(pairs);
    assert_eq!(
        mutations.root(),
        root_empty,
        "prospective root for batch removal did not match actual root",
    );
    let old_root = smt.root();
    let revert = apply_mutations(&mut smt, mutations);
    assert_eq!(smt.root(), root_empty, "mutations before and after apply did not match");
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), old_root, "reverse mutations new root did not match");
    assert_eq!(
        revert.new_pairs,
        UnorderedMap::from_iter([(key_1, value_1), (key_2, value_2), (key_3, value_3)]),
        "reverse mutations pairs did not match"
    );

    let pairs = vec![(key_3, value_3), (key_1, value_1), (key_2, value_2)];
    let mutations = smt.compute_mutations(pairs);
    assert_eq!(mutations.root(), root_3);
    smt.apply_mutations(mutations).unwrap();
    assert_eq!(smt.root(), root_3);
}

#[test]
fn test_mutations_revert() {
    let mut smt = Smt::default();

    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, Felt::new(1)]);
    let key_2: RpoDigest =
        RpoDigest::from([2_u32.into(), 2_u32.into(), 2_u32.into(), Felt::new(2)]);
    let key_3: RpoDigest =
        RpoDigest::from([0_u32.into(), 0_u32.into(), 0_u32.into(), Felt::new(3)]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];
    let value_3 = [3_u32.into(); WORD_SIZE];

    smt.insert(key_1, value_1);
    smt.insert(key_2, value_2);

    let mutations =
        smt.compute_mutations(vec![(key_1, EMPTY_WORD), (key_2, value_1), (key_3, value_3)]);

    let original = smt.clone();

    let revert = smt.apply_mutations_with_reversion(mutations).unwrap();
    assert_eq!(revert.old_root, smt.root(), "reverse mutations old root did not match");
    assert_eq!(revert.root(), original.root(), "reverse mutations new root did not match");

    smt.apply_mutations(revert).unwrap();

    assert_eq!(smt, original, "SMT with applied revert mutations did not match original SMT");
}

#[test]
fn test_mutation_set_serialization() {
    let mut smt = Smt::default();

    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, Felt::new(1)]);
    let key_2: RpoDigest =
        RpoDigest::from([2_u32.into(), 2_u32.into(), 2_u32.into(), Felt::new(2)]);
    let key_3: RpoDigest =
        RpoDigest::from([0_u32.into(), 0_u32.into(), 0_u32.into(), Felt::new(3)]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];
    let value_3 = [3_u32.into(); WORD_SIZE];

    smt.insert(key_1, value_1);
    smt.insert(key_2, value_2);

    let mutations =
        smt.compute_mutations(vec![(key_1, EMPTY_WORD), (key_2, value_1), (key_3, value_3)]);

    let serialized = mutations.to_bytes();
    let deserialized =
        MutationSet::<SMT_DEPTH, RpoDigest, Word>::read_from_bytes(&serialized).unwrap();

    assert_eq!(deserialized, mutations, "deserialized mutations did not match original");

    let revert = smt.apply_mutations_with_reversion(mutations).unwrap();

    let serialized = revert.to_bytes();
    let deserialized =
        MutationSet::<SMT_DEPTH, RpoDigest, Word>::read_from_bytes(&serialized).unwrap();

    assert_eq!(deserialized, revert, "deserialized mutations did not match original");
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
    let key_1 = RpoDigest::from([ONE, ONE, ONE, ONE]);
    let key_2 = RpoDigest::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];
    let entries = [(key_1, value_1), (key_2, value_2)];

    let smt = Smt::with_entries(entries).unwrap();

    let mut expected = Vec::from_iter(entries);
    expected.sort_by_key(|(k, _)| *k);
    let mut actual: Vec<_> = smt.entries().cloned().collect();
    actual.sort_by_key(|(k, _)| *k);

    assert_eq!(actual, expected);
}

/// Tests that `EMPTY_ROOT` constant generated in the `Smt` equals to the root of the empty tree of
/// depth 64
#[test]
fn test_smt_check_empty_root_constant() {
    // get the root of the empty tree of depth 64
    let empty_root_64_depth = EmptySubtreeRoots::empty_hashes(64)[0];

    assert_eq!(empty_root_64_depth, Smt::EMPTY_ROOT);
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

/// Applies mutations with and without reversion to the given SMT, comparing resulting SMTs,
/// returning mutation set for reversion.
fn apply_mutations(
    smt: &mut Smt,
    mutation_set: MutationSet<SMT_DEPTH, RpoDigest, Word>,
) -> MutationSet<SMT_DEPTH, RpoDigest, Word> {
    let mut smt2 = smt.clone();

    let reversion = smt.apply_mutations_with_reversion(mutation_set.clone()).unwrap();
    smt2.apply_mutations(mutation_set).unwrap();

    assert_eq!(&smt2, smt);

    reversion
}

// CONCURRENT TESTS
// --------------------------------------------------------------------------------------------

#[cfg(feature = "concurrent")]
mod concurrent_tests {
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };

    use rand::{prelude::IteratorRandom, thread_rng, Rng};

    use super::*;
    use crate::{
        merkle::smt::{
            full::{
                build_subtree, PairComputations, SubtreeLeaf, SubtreeLeavesIter, COLS_PER_SUBTREE,
                SUBTREE_DEPTH,
            },
            InnerNode, NodeMutations, SparseMerkleTree, UnorderedMap,
        },
        Word, ONE,
    };

    fn smtleaf_to_subtree_leaf(leaf: &SmtLeaf) -> SubtreeLeaf {
        SubtreeLeaf {
            col: leaf.index().index.value(),
            hash: leaf.hash(),
        }
    }

    #[test]
    fn test_sorted_pairs_to_leaves() {
        let entries: Vec<(RpoDigest, Word)> = vec![
            // Subtree 0.
            (RpoDigest::new([ONE, ONE, ONE, Felt::new(16)]), [ONE; 4]),
            (RpoDigest::new([ONE, ONE, ONE, Felt::new(17)]), [ONE; 4]),
            // Leaf index collision.
            (RpoDigest::new([ONE, ONE, Felt::new(10), Felt::new(20)]), [ONE; 4]),
            (RpoDigest::new([ONE, ONE, Felt::new(20), Felt::new(20)]), [ONE; 4]),
            // Subtree 1. Normal single leaf again.
            (RpoDigest::new([ONE, ONE, ONE, Felt::new(400)]), [ONE; 4]), // Subtree boundary.
            (RpoDigest::new([ONE, ONE, ONE, Felt::new(401)]), [ONE; 4]),
            // Subtree 2. Another normal leaf.
            (RpoDigest::new([ONE, ONE, ONE, Felt::new(1024)]), [ONE; 4]),
        ];

        let control = Smt::with_entries_sequential(entries.clone()).unwrap();

        let control_leaves: Vec<SmtLeaf> = {
            let mut entries_iter = entries.iter().cloned();
            let mut next_entry = || entries_iter.next().unwrap();
            let control_leaves = vec![
                // Subtree 0.
                SmtLeaf::Single(next_entry()),
                SmtLeaf::Single(next_entry()),
                SmtLeaf::new_multiple(vec![next_entry(), next_entry()]).unwrap(),
                // Subtree 1.
                SmtLeaf::Single(next_entry()),
                SmtLeaf::Single(next_entry()),
                // Subtree 2.
                SmtLeaf::Single(next_entry()),
            ];
            assert_eq!(entries_iter.next(), None);
            control_leaves
        };

        let control_subtree_leaves: Vec<Vec<SubtreeLeaf>> = {
            let mut control_leaves_iter = control_leaves.iter();
            let mut next_leaf = || control_leaves_iter.next().unwrap();

            let control_subtree_leaves: Vec<Vec<SubtreeLeaf>> = [
                // Subtree 0.
                vec![next_leaf(), next_leaf(), next_leaf()],
                // Subtree 1.
                vec![next_leaf(), next_leaf()],
                // Subtree 2.
                vec![next_leaf()],
            ]
            .map(|subtree| subtree.into_iter().map(smtleaf_to_subtree_leaf).collect())
            .to_vec();
            assert_eq!(control_leaves_iter.next(), None);
            control_subtree_leaves
        };

        let subtrees: PairComputations<u64, SmtLeaf> = Smt::sorted_pairs_to_leaves(entries);
        // This will check that the hashes, columns, and subtree assignments all match.
        assert_eq!(subtrees.leaves, control_subtree_leaves);

        // Flattening and re-separating out the leaves into subtrees should have the same result.
        let mut all_leaves: Vec<SubtreeLeaf> =
            subtrees.leaves.clone().into_iter().flatten().collect();
        let re_grouped: Vec<Vec<_>> = SubtreeLeavesIter::from_leaves(&mut all_leaves).collect();
        assert_eq!(subtrees.leaves, re_grouped);

        // Then finally we might as well check the computed leaf nodes too.
        let control_leaves: BTreeMap<u64, SmtLeaf> = control
            .leaves()
            .map(|(index, value)| (index.index.value(), value.clone()))
            .collect();

        for (column, test_leaf) in subtrees.nodes {
            if test_leaf.is_empty() {
                continue;
            }
            let control_leaf = control_leaves
                .get(&column)
                .unwrap_or_else(|| panic!("no leaf node found for column {column}"));
            assert_eq!(control_leaf, &test_leaf);
        }
    }

    // Helper for the below tests.
    fn generate_entries(pair_count: u64) -> Vec<(RpoDigest, Word)> {
        (0..pair_count)
            .map(|i| {
                let leaf_index = ((i as f64 / pair_count as f64) * (pair_count as f64)) as u64;
                let key = RpoDigest::new([ONE, ONE, Felt::new(i), Felt::new(leaf_index)]);
                let value = [ONE, ONE, ONE, Felt::new(i)];
                (key, value)
            })
            .collect()
    }

    fn generate_updates(entries: Vec<(RpoDigest, Word)>, updates: usize) -> Vec<(RpoDigest, Word)> {
        const REMOVAL_PROBABILITY: f64 = 0.2;
        let mut rng = thread_rng();

        // Assertion to ensure input keys are unique
        assert!(
            entries.iter().map(|(key, _)| key).collect::<BTreeSet<_>>().len() == entries.len(),
            "Input entries contain duplicate keys!"
        );

        let mut sorted_entries: Vec<(RpoDigest, Word)> = entries
            .into_iter()
            .choose_multiple(&mut rng, updates)
            .into_iter()
            .map(|(key, _)| {
                let value = if rng.gen_bool(REMOVAL_PROBABILITY) {
                    EMPTY_WORD
                } else {
                    [ONE, ONE, ONE, Felt::new(rng.gen())]
                };

                (key, value)
            })
            .collect();
        sorted_entries.sort_by_key(|(key, _)| Smt::key_to_leaf_index(key).value());
        sorted_entries
    }

    #[test]
    fn test_single_subtree() {
        // A single subtree's worth of leaves.
        const PAIR_COUNT: u64 = COLS_PER_SUBTREE;

        let entries = generate_entries(PAIR_COUNT);

        let control = Smt::with_entries_sequential(entries.clone()).unwrap();

        // `entries` should already be sorted by nature of how we constructed it.
        let leaves = Smt::sorted_pairs_to_leaves(entries).leaves;
        let leaves = leaves.into_iter().next().unwrap();

        let (first_subtree, subtree_root) = build_subtree(leaves, SMT_DEPTH, SMT_DEPTH);
        assert!(!first_subtree.is_empty());

        // The inner nodes computed from that subtree should match the nodes in our control tree.
        for (index, node) in first_subtree.into_iter() {
            let control = control.get_inner_node(index);
            assert_eq!(
                control, node,
                "subtree-computed node at index {index:?} does not match control",
            );
        }

        // The root returned should also match the equivalent node in the control tree.
        let control_root_index =
            NodeIndex::new(SMT_DEPTH - SUBTREE_DEPTH, subtree_root.col).expect("Valid root index");
        let control_root_node = control.get_inner_node(control_root_index);
        let control_hash = control_root_node.hash();
        assert_eq!(
            control_hash, subtree_root.hash,
            "Subtree-computed root at index {control_root_index:?} does not match control"
        );
    }

    // Test that not just can we compute a subtree correctly, but we can feed the results of one
    // subtree into computing another. In other words, test that `build_subtree()` is correctly
    // composable.
    #[test]
    fn test_two_subtrees() {
        // Two subtrees' worth of leaves.
        const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 2;

        let entries = generate_entries(PAIR_COUNT);

        let control = Smt::with_entries_sequential(entries.clone()).unwrap();

        let PairComputations { leaves, .. } = Smt::sorted_pairs_to_leaves(entries);
        // With two subtrees' worth of leaves, we should have exactly two subtrees.
        let [first, second]: [Vec<_>; 2] = leaves.try_into().unwrap();
        assert_eq!(first.len() as u64, PAIR_COUNT / 2);
        assert_eq!(first.len(), second.len());

        let mut current_depth = SMT_DEPTH;
        let mut next_leaves: Vec<SubtreeLeaf> = Default::default();

        let (first_nodes, first_root) = build_subtree(first, SMT_DEPTH, current_depth);
        next_leaves.push(first_root);

        let (second_nodes, second_root) = build_subtree(second, SMT_DEPTH, current_depth);
        next_leaves.push(second_root);

        // All new inner nodes + the new subtree-leaves should be 512, for one depth-cycle.
        let total_computed = first_nodes.len() + second_nodes.len() + next_leaves.len();
        assert_eq!(total_computed as u64, PAIR_COUNT);

        // Verify the computed nodes of both subtrees.
        let computed_nodes = first_nodes.clone().into_iter().chain(second_nodes);
        for (index, test_node) in computed_nodes {
            let control_node = control.get_inner_node(index);
            assert_eq!(
                control_node, test_node,
                "subtree-computed node at index {index:?} does not match control",
            );
        }

        current_depth -= SUBTREE_DEPTH;

        let (nodes, root_leaf) = build_subtree(next_leaves, SMT_DEPTH, current_depth);
        assert_eq!(nodes.len(), SUBTREE_DEPTH as usize);
        assert_eq!(root_leaf.col, 0);

        for (index, test_node) in nodes {
            let control_node = control.get_inner_node(index);
            assert_eq!(
                control_node, test_node,
                "subtree-computed node at index {index:?} does not match control",
            );
        }

        let index = NodeIndex::new(current_depth - SUBTREE_DEPTH, root_leaf.col).unwrap();
        let control_root = control.get_inner_node(index).hash();
        assert_eq!(control_root, root_leaf.hash, "Root mismatch");
    }

    #[test]
    fn test_singlethreaded_subtrees() {
        const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

        let entries = generate_entries(PAIR_COUNT);

        let control = Smt::with_entries_sequential(entries.clone()).unwrap();

        let mut accumulated_nodes: BTreeMap<NodeIndex, InnerNode> = Default::default();

        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: test_leaves,
        } = Smt::sorted_pairs_to_leaves(entries);

        for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
            // There's no flat_map_unzip(), so this is the best we can do.
            let (nodes, mut subtree_roots): (Vec<UnorderedMap<_, _>>, Vec<SubtreeLeaf>) =
                leaf_subtrees
                    .into_iter()
                    .enumerate()
                    .map(|(i, subtree)| {
                        // Pre-assertions.
                        assert!(
                            subtree.is_sorted(),
                            "subtree {i} at bottom-depth {current_depth} is not sorted",
                        );
                        assert!(
                            !subtree.is_empty(),
                            "subtree {i} at bottom-depth {current_depth} is empty!",
                        );

                        // Do actual things.
                        let (nodes, subtree_root) =
                            build_subtree(subtree, SMT_DEPTH, current_depth);

                        // Post-assertions.
                        for (&index, test_node) in nodes.iter() {
                            let control_node = control.get_inner_node(index);
                            assert_eq!(
                            test_node, &control_node,
                            "depth {} subtree {}: test node does not match control at index {:?}",
                            current_depth, i, index,
                        );
                        }

                        (nodes, subtree_root)
                    })
                    .unzip();

            // Update state between each depth iteration.

            leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            accumulated_nodes.extend(nodes.into_iter().flatten());

            assert!(!leaf_subtrees.is_empty(), "on depth {current_depth}");
        }

        // Make sure the true leaves match, first checking length and then checking each individual
        // leaf.
        let control_leaves: BTreeMap<_, _> = control.leaves().collect();
        let control_leaves_len = control_leaves.len();
        let test_leaves_len = test_leaves.len();
        assert_eq!(test_leaves_len, control_leaves_len);
        for (col, ref test_leaf) in test_leaves {
            let index = LeafIndex::new_max_depth(col);
            let &control_leaf = control_leaves.get(&index).unwrap();
            assert_eq!(test_leaf, control_leaf, "test leaf at column {col} does not match control");
        }

        // Make sure the inner nodes match, checking length first and then each individual leaf.
        let control_nodes_len = control.inner_nodes().count();
        let test_nodes_len = accumulated_nodes.len();
        assert_eq!(test_nodes_len, control_nodes_len);
        for (index, test_node) in accumulated_nodes.clone() {
            let control_node = control.get_inner_node(index);
            assert_eq!(test_node, control_node, "test node does not match control at {index:?}");
        }

        // After the last iteration of the above for loop, we should have the new root node actually
        // in two places: one in `accumulated_nodes`, and the other as the "next leaves" return from
        // `build_subtree()`. So let's check both!

        let control_root = control.get_inner_node(NodeIndex::root());

        // That for loop should have left us with only one leaf subtree...
        let [leaf_subtree]: [Vec<_>; 1] = leaf_subtrees.try_into().unwrap();
        // which itself contains only one 'leaf'...
        let [root_leaf]: [SubtreeLeaf; 1] = leaf_subtree.try_into().unwrap();
        // which matches the expected root.
        assert_eq!(control.root(), root_leaf.hash);

        // Likewise `accumulated_nodes` should contain a node at the root index...
        assert!(accumulated_nodes.contains_key(&NodeIndex::root()));
        // and it should match our actual root.
        let test_root = accumulated_nodes.get(&NodeIndex::root()).unwrap();
        assert_eq!(control_root, *test_root);
        // And of course the root we got from each place should match.
        assert_eq!(control.root(), root_leaf.hash);
    }

    /// The parallel version of `test_singlethreaded_subtree()`.
    #[test]
    fn test_multithreaded_subtrees() {
        use rayon::prelude::*;

        const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

        let entries = generate_entries(PAIR_COUNT);

        let control = Smt::with_entries_sequential(entries.clone()).unwrap();

        let mut accumulated_nodes: BTreeMap<NodeIndex, InnerNode> = Default::default();

        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: test_leaves,
        } = Smt::sorted_pairs_to_leaves(entries);

        for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
            let (nodes, mut subtree_roots): (Vec<UnorderedMap<_, _>>, Vec<SubtreeLeaf>) =
                leaf_subtrees
                    .into_par_iter()
                    .enumerate()
                    .map(|(i, subtree)| {
                        // Pre-assertions.
                        assert!(
                            subtree.is_sorted(),
                            "subtree {i} at bottom-depth {current_depth} is not sorted",
                        );
                        assert!(
                            !subtree.is_empty(),
                            "subtree {i} at bottom-depth {current_depth} is empty!",
                        );

                        let (nodes, subtree_root) =
                            build_subtree(subtree, SMT_DEPTH, current_depth);

                        // Post-assertions.
                        for (&index, test_node) in nodes.iter() {
                            let control_node = control.get_inner_node(index);
                            assert_eq!(
                            test_node, &control_node,
                            "depth {} subtree {}: test node does not match control at index {:?}",
                            current_depth, i, index,
                        );
                        }

                        (nodes, subtree_root)
                    })
                    .unzip();

            leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            accumulated_nodes.extend(nodes.into_iter().flatten());

            assert!(!leaf_subtrees.is_empty(), "on depth {current_depth}");
        }

        // Make sure the true leaves match, checking length first and then each individual leaf.
        let control_leaves: BTreeMap<_, _> = control.leaves().collect();
        let control_leaves_len = control_leaves.len();
        let test_leaves_len = test_leaves.len();
        assert_eq!(test_leaves_len, control_leaves_len);
        for (col, ref test_leaf) in test_leaves {
            let index = LeafIndex::new_max_depth(col);
            let &control_leaf = control_leaves.get(&index).unwrap();
            assert_eq!(test_leaf, control_leaf);
        }

        // Make sure the inner nodes match, checking length first and then each individual leaf.
        let control_nodes_len = control.inner_nodes().count();
        let test_nodes_len = accumulated_nodes.len();
        assert_eq!(test_nodes_len, control_nodes_len);
        for (index, test_node) in accumulated_nodes.clone() {
            let control_node = control.get_inner_node(index);
            assert_eq!(test_node, control_node, "test node does not match control at {index:?}");
        }

        // After the last iteration of the above for loop, we should have the new root node actually
        // in two places: one in `accumulated_nodes`, and the other as the "next leaves" return from
        // `build_subtree()`. So let's check both!

        let control_root = control.get_inner_node(NodeIndex::root());

        // That for loop should have left us with only one leaf subtree...
        let [leaf_subtree]: [_; 1] = leaf_subtrees.try_into().unwrap();
        // which itself contains only one 'leaf'...
        let [root_leaf]: [_; 1] = leaf_subtree.try_into().unwrap();
        // which matches the expected root.
        assert_eq!(control.root(), root_leaf.hash);

        // Likewise `accumulated_nodes` should contain a node at the root index...
        assert!(accumulated_nodes.contains_key(&NodeIndex::root()));
        // and it should match our actual root.
        let test_root = accumulated_nodes.get(&NodeIndex::root()).unwrap();
        assert_eq!(control_root, *test_root);
        // And of course the root we got from each place should match.
        assert_eq!(control.root(), root_leaf.hash);
    }

    #[test]
    fn test_with_entries_concurrent() {
        const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

        let entries = generate_entries(PAIR_COUNT);

        let control = Smt::with_entries_sequential(entries.clone()).unwrap();

        let smt = Smt::with_entries(entries.clone()).unwrap();
        assert_eq!(smt.root(), control.root());
        assert_eq!(smt, control);
    }

    /// Concurrent mutations
    #[test]
    fn test_singlethreaded_subtree_mutations() {
        const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

        let entries = generate_entries(PAIR_COUNT);
        let updates = generate_updates(entries.clone(), 1000);

        let tree = Smt::with_entries_sequential(entries.clone()).unwrap();
        let control = tree.compute_mutations_sequential(updates.clone());

        let mut node_mutations = NodeMutations::default();

        let (mut subtree_leaves, new_pairs) = tree.sorted_pairs_to_mutated_subtree_leaves(updates);

        for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
            // There's no flat_map_unzip(), so this is the best we can do.
            let (mutations_per_subtree, mut subtree_roots): (Vec<_>, Vec<_>) = subtree_leaves
                .into_iter()
                .enumerate()
                .map(|(i, subtree)| {
                    // Pre-assertions.
                    assert!(
                        subtree.is_sorted(),
                        "subtree {i} at bottom-depth {current_depth} is not sorted",
                    );
                    assert!(
                        !subtree.is_empty(),
                        "subtree {i} at bottom-depth {current_depth} is empty!",
                    );

                    // Calculate the mutations for this subtree.
                    let (mutations_per_subtree, subtree_root) =
                        tree.build_subtree_mutations(subtree, SMT_DEPTH, current_depth);

                    // Check that the mutations match the control tree.
                    for (&index, mutation) in mutations_per_subtree.iter() {
                        let control_mutation = control.node_mutations().get(&index).unwrap();
                        assert_eq!(
                            control_mutation, mutation,
                            "depth {} subtree {}: mutation does not match control at index {:?}",
                            current_depth, i, index,
                        );
                    }

                    (mutations_per_subtree, subtree_root)
                })
                .unzip();

            subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            node_mutations.extend(mutations_per_subtree.into_iter().flatten());

            assert!(!subtree_leaves.is_empty(), "on depth {current_depth}");
        }

        let [subtree]: [Vec<_>; 1] = subtree_leaves.try_into().unwrap();
        let [root_leaf]: [SubtreeLeaf; 1] = subtree.try_into().unwrap();
        // Check that the new root matches the control.
        assert_eq!(control.new_root, root_leaf.hash);

        // Check that the node mutations match the control.
        assert_eq!(control.node_mutations().len(), node_mutations.len());
        for (&index, mutation) in control.node_mutations().iter() {
            let test_mutation = node_mutations.get(&index).unwrap();
            assert_eq!(test_mutation, mutation);
        }
        // Check that the new pairs match the control
        assert_eq!(control.new_pairs.len(), new_pairs.len());
        for (&key, &value) in control.new_pairs.iter() {
            let test_value = new_pairs.get(&key).unwrap();
            assert_eq!(test_value, &value);
        }
    }

    #[test]
    fn test_compute_mutations_parallel() {
        const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

        let entries = generate_entries(PAIR_COUNT);
        let tree = Smt::with_entries(entries.clone()).unwrap();

        let updates = generate_updates(entries, 1000);

        let control = tree.compute_mutations_sequential(updates.clone());
        let mutations = tree.compute_mutations(updates);

        assert_eq!(mutations.root(), control.root());
        assert_eq!(mutations.old_root(), control.old_root());
        assert_eq!(mutations.node_mutations(), control.node_mutations());
        assert_eq!(mutations.new_pairs(), control.new_pairs());
    }
}
