use super::{
    super::{super::ONE, super::WORD_SIZE, Felt, MerkleStore, EMPTY_WORD, ZERO},
    EmptySubtreeRoots, InnerNodeInfo, NodeIndex, Rpo256, RpoDigest, TieredSmt, Vec, Word,
};

// INSERTION TESTS
// ================================================================================================

#[test]
fn tsmt_insert_one() {
    let mut smt = TieredSmt::default();
    let mut store = MerkleStore::default();

    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let value = [ONE; WORD_SIZE];

    // since the tree is empty, the first node will be inserted at depth 16 and the index will be
    // 16 most significant bits of the key
    let index = NodeIndex::make(16, raw >> 48);
    let leaf_node = build_leaf_node(key, value, 16);
    let tree_root = store.set_node(smt.root(), index, leaf_node).unwrap().root;

    smt.insert(key, value);

    assert_eq!(smt.root(), tree_root);

    // make sure the value was inserted, and the node is at the expected index
    assert_eq!(smt.get_value(key), value);
    assert_eq!(smt.get_node(index).unwrap(), leaf_node);

    // make sure the paths we get from the store and the tree match
    let expected_path = store.get_path(tree_root, index).unwrap();
    assert_eq!(smt.get_path(index).unwrap(), expected_path.path);

    // make sure inner nodes match
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    assert_eq!(actual_nodes.len(), expected_nodes.len());
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));

    // make sure leaves are returned correctly
    let mut leaves = smt.upper_leaves();
    assert_eq!(leaves.next(), Some((leaf_node, key, value)));
    assert_eq!(leaves.next(), None);
}

#[test]
fn tsmt_insert_two_16() {
    let mut smt = TieredSmt::default();
    let mut store = MerkleStore::default();

    // --- insert the first value ---------------------------------------------
    let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let val_a = [ONE; WORD_SIZE];
    smt.insert(key_a, val_a);

    // --- insert the second value --------------------------------------------
    // the key for this value has the same 16-bit prefix as the key for the first value,
    // thus, on insertions, both values should be pushed to depth 32 tier
    let raw_b = 0b_10101010_10101010_10011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let val_b = [Felt::new(2); WORD_SIZE];
    smt.insert(key_b, val_b);

    // --- build Merkle store with equivalent data ----------------------------
    let mut tree_root = get_init_root();
    let index_a = NodeIndex::make(32, raw_a >> 32);
    let leaf_node_a = build_leaf_node(key_a, val_a, 32);
    tree_root = store.set_node(tree_root, index_a, leaf_node_a).unwrap().root;

    let index_b = NodeIndex::make(32, raw_b >> 32);
    let leaf_node_b = build_leaf_node(key_b, val_b, 32);
    tree_root = store.set_node(tree_root, index_b, leaf_node_b).unwrap().root;

    // --- verify that data is consistent between store and tree --------------

    assert_eq!(smt.root(), tree_root);

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root, index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root, index_b).unwrap().path;
    assert_eq!(smt.get_path(index_b).unwrap(), expected_path);

    // make sure inner nodes match - the store contains more entries because it keeps track of
    // all prior state - so, we don't check that the number of inner nodes is the same in both
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));

    // make sure leaves are returned correctly
    let mut leaves = smt.upper_leaves();
    assert_eq!(leaves.next(), Some((leaf_node_a, key_a, val_a)));
    assert_eq!(leaves.next(), Some((leaf_node_b, key_b, val_b)));
    assert_eq!(leaves.next(), None);
}

#[test]
fn tsmt_insert_two_32() {
    let mut smt = TieredSmt::default();
    let mut store = MerkleStore::default();

    // --- insert the first value ---------------------------------------------
    let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let val_a = [ONE; WORD_SIZE];
    smt.insert(key_a, val_a);

    // --- insert the second value --------------------------------------------
    // the key for this value has the same 32-bit prefix as the key for the first value,
    // thus, on insertions, both values should be pushed to depth 48 tier
    let raw_b = 0b_10101010_10101010_00011111_11111111_00010110_10010011_11100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let val_b = [Felt::new(2); WORD_SIZE];
    smt.insert(key_b, val_b);

    // --- build Merkle store with equivalent data ----------------------------
    let mut tree_root = get_init_root();
    let index_a = NodeIndex::make(48, raw_a >> 16);
    let leaf_node_a = build_leaf_node(key_a, val_a, 48);
    tree_root = store.set_node(tree_root, index_a, leaf_node_a).unwrap().root;

    let index_b = NodeIndex::make(48, raw_b >> 16);
    let leaf_node_b = build_leaf_node(key_b, val_b, 48);
    tree_root = store.set_node(tree_root, index_b, leaf_node_b).unwrap().root;

    // --- verify that data is consistent between store and tree --------------

    assert_eq!(smt.root(), tree_root);

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root, index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root, index_b).unwrap().path;
    assert_eq!(smt.get_path(index_b).unwrap(), expected_path);

    // make sure inner nodes match - the store contains more entries because it keeps track of
    // all prior state - so, we don't check that the number of inner nodes is the same in both
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));
}

#[test]
fn tsmt_insert_three() {
    let mut smt = TieredSmt::default();
    let mut store = MerkleStore::default();

    // --- insert the first value ---------------------------------------------
    let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let val_a = [ONE; WORD_SIZE];
    smt.insert(key_a, val_a);

    // --- insert the second value --------------------------------------------
    // the key for this value has the same 16-bit prefix as the key for the first value,
    // thus, on insertions, both values should be pushed to depth 32 tier
    let raw_b = 0b_10101010_10101010_10011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let val_b = [Felt::new(2); WORD_SIZE];
    smt.insert(key_b, val_b);

    // --- insert the third value ---------------------------------------------
    // the key for this value has the same 16-bit prefix as the keys for the first two,
    // values; thus, on insertions, it will be inserted into depth 32 tier, but will not
    // affect locations of the other two values
    let raw_c = 0b_10101010_10101010_11011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    let val_c = [Felt::new(3); WORD_SIZE];
    smt.insert(key_c, val_c);

    // --- build Merkle store with equivalent data ----------------------------
    let mut tree_root = get_init_root();
    let index_a = NodeIndex::make(32, raw_a >> 32);
    let leaf_node_a = build_leaf_node(key_a, val_a, 32);
    tree_root = store.set_node(tree_root, index_a, leaf_node_a).unwrap().root;

    let index_b = NodeIndex::make(32, raw_b >> 32);
    let leaf_node_b = build_leaf_node(key_b, val_b, 32);
    tree_root = store.set_node(tree_root, index_b, leaf_node_b).unwrap().root;

    let index_c = NodeIndex::make(32, raw_c >> 32);
    let leaf_node_c = build_leaf_node(key_c, val_c, 32);
    tree_root = store.set_node(tree_root, index_c, leaf_node_c).unwrap().root;

    // --- verify that data is consistent between store and tree --------------

    assert_eq!(smt.root(), tree_root);

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root, index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root, index_b).unwrap().path;
    assert_eq!(smt.get_path(index_b).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_c), val_c);
    assert_eq!(smt.get_node(index_c).unwrap(), leaf_node_c);
    let expected_path = store.get_path(tree_root, index_c).unwrap().path;
    assert_eq!(smt.get_path(index_c).unwrap(), expected_path);

    // make sure inner nodes match - the store contains more entries because it keeps track of
    // all prior state - so, we don't check that the number of inner nodes is the same in both
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));
}

// UPDATE TESTS
// ================================================================================================

#[test]
fn tsmt_update() {
    let mut smt = TieredSmt::default();
    let mut store = MerkleStore::default();

    // --- insert a value into the tree ---------------------------------------
    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let value_a = [ONE; WORD_SIZE];
    smt.insert(key, value_a);

    // --- update the value ---------------------------------------------------
    let value_b = [Felt::new(2); WORD_SIZE];
    smt.insert(key, value_b);

    // --- verify consistency -------------------------------------------------
    let mut tree_root = get_init_root();
    let index = NodeIndex::make(16, raw >> 48);
    let leaf_node = build_leaf_node(key, value_b, 16);
    tree_root = store.set_node(tree_root, index, leaf_node).unwrap().root;

    assert_eq!(smt.root(), tree_root);

    assert_eq!(smt.get_value(key), value_b);
    assert_eq!(smt.get_node(index).unwrap(), leaf_node);
    let expected_path = store.get_path(tree_root, index).unwrap().path;
    assert_eq!(smt.get_path(index).unwrap(), expected_path);

    // make sure inner nodes match - the store contains more entries because it keeps track of
    // all prior state - so, we don't check that the number of inner nodes is the same in both
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));
}

// DELETION TESTS
// ================================================================================================

#[test]
fn tsmt_delete_16() {
    let mut smt = TieredSmt::default();

    // --- insert a value into the tree ---------------------------------------
    let smt0 = smt.clone();
    let raw_a = 0b_01010101_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let value_a = [ONE, ONE, ONE, ONE];
    smt.insert(key_a, value_a);

    // --- insert another value into the tree ---------------------------------
    let smt1 = smt.clone();
    let raw_b = 0b_01011111_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let value_b = [ONE, ONE, ONE, ZERO];
    smt.insert(key_b, value_b);

    // --- delete the last inserted value -------------------------------------
    assert_eq!(smt.insert(key_b, EMPTY_WORD), value_b);
    assert_eq!(smt, smt1);

    // --- delete the first inserted value ------------------------------------
    assert_eq!(smt.insert(key_a, EMPTY_WORD), value_a);
    assert_eq!(smt, smt0);
}

#[test]
fn tsmt_delete_32() {
    let mut smt = TieredSmt::default();

    // --- insert a value into the tree ---------------------------------------
    let smt0 = smt.clone();
    let raw_a = 0b_01010101_01101100_01111111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let value_a = [ONE, ONE, ONE, ONE];
    smt.insert(key_a, value_a);

    // --- insert another with the same 16-bit prefix into the tree -----------
    let smt1 = smt.clone();
    let raw_b = 0b_01010101_01101100_00111111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let value_b = [ONE, ONE, ONE, ZERO];
    smt.insert(key_b, value_b);

    // --- insert the 3rd value with the same 16-bit prefix into the tree -----
    let smt2 = smt.clone();
    let raw_c = 0b_01010101_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    let value_c = [ONE, ONE, ZERO, ZERO];
    smt.insert(key_c, value_c);

    // --- delete the last inserted value -------------------------------------
    assert_eq!(smt.insert(key_c, EMPTY_WORD), value_c);
    assert_eq!(smt, smt2);

    // --- delete the last inserted value -------------------------------------
    assert_eq!(smt.insert(key_b, EMPTY_WORD), value_b);
    assert_eq!(smt, smt1);

    // --- delete the first inserted value ------------------------------------
    assert_eq!(smt.insert(key_a, EMPTY_WORD), value_a);
    assert_eq!(smt, smt0);
}

#[test]
fn tsmt_delete_48_same_32_bit_prefix() {
    let mut smt = TieredSmt::default();

    // test the case when all values share the same 32-bit prefix

    // --- insert a value into the tree ---------------------------------------
    let smt0 = smt.clone();
    let raw_a = 0b_01010101_01010101_11111111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let value_a = [ONE, ONE, ONE, ONE];
    smt.insert(key_a, value_a);

    // --- insert another with the same 32-bit prefix into the tree -----------
    let smt1 = smt.clone();
    let raw_b = 0b_01010101_01010101_11111111_11111111_11010110_10010011_11100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let value_b = [ONE, ONE, ONE, ZERO];
    smt.insert(key_b, value_b);

    // --- insert the 3rd value with the same 32-bit prefix into the tree -----
    let smt2 = smt.clone();
    let raw_c = 0b_01010101_01010101_11111111_11111111_11110110_10010011_11100000_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    let value_c = [ONE, ONE, ZERO, ZERO];
    smt.insert(key_c, value_c);

    // --- delete the last inserted value -------------------------------------
    assert_eq!(smt.insert(key_c, EMPTY_WORD), value_c);
    assert_eq!(smt, smt2);

    // --- delete the last inserted value -------------------------------------
    assert_eq!(smt.insert(key_b, EMPTY_WORD), value_b);
    assert_eq!(smt, smt1);

    // --- delete the first inserted value ------------------------------------
    assert_eq!(smt.insert(key_a, EMPTY_WORD), value_a);
    assert_eq!(smt, smt0);
}

#[test]
fn tsmt_delete_48_mixed_prefix() {
    let mut smt = TieredSmt::default();

    // test the case when some values share a 32-bit prefix and others share a 16-bit prefix

    // --- insert a value into the tree ---------------------------------------
    let smt0 = smt.clone();
    let raw_a = 0b_01010101_01010101_11111111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let value_a = [ONE, ONE, ONE, ONE];
    smt.insert(key_a, value_a);

    // --- insert another with the same 16-bit prefix into the tree -----------
    let smt1 = smt.clone();
    let raw_b = 0b_01010101_01010101_01111111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let value_b = [ONE, ONE, ONE, ZERO];
    smt.insert(key_b, value_b);

    // --- insert a value with the same 32-bit prefix as the first value -----
    let smt2 = smt.clone();
    let raw_c = 0b_01010101_01010101_11111111_11111111_11010110_10010011_11100000_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    let value_c = [ONE, ONE, ZERO, ZERO];
    smt.insert(key_c, value_c);

    // --- insert another value with the same 32-bit prefix as the first value
    let smt3 = smt.clone();
    let raw_d = 0b_01010101_01010101_11111111_11111111_11110110_10010011_11100000_00000000_u64;
    let key_d = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_d)]);
    let value_d = [ONE, ZERO, ZERO, ZERO];
    smt.insert(key_d, value_d);

    // --- delete the inserted values one-by-one ------------------------------
    assert_eq!(smt.insert(key_d, EMPTY_WORD), value_d);
    assert_eq!(smt, smt3);

    assert_eq!(smt.insert(key_c, EMPTY_WORD), value_c);
    assert_eq!(smt, smt2);

    assert_eq!(smt.insert(key_b, EMPTY_WORD), value_b);
    assert_eq!(smt, smt1);

    assert_eq!(smt.insert(key_a, EMPTY_WORD), value_a);
    assert_eq!(smt, smt0);
}

#[test]
fn tsmt_delete_64() {
    let mut smt = TieredSmt::default();

    // test the case when all values share the same 48-bit prefix

    // --- insert a value into the tree ---------------------------------------
    let smt0 = smt.clone();
    let raw_a = 0b_01010101_01010101_11111111_11111111_10110101_10101010_11111100_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let value_a = [ONE, ONE, ONE, ONE];
    smt.insert(key_a, value_a);

    // --- insert a value with the same 48-bit prefix into the tree -----------
    let smt1 = smt.clone();
    let raw_b = 0b_01010101_01010101_11111111_11111111_10110101_10101010_10111100_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let value_b = [ONE, ONE, ONE, ZERO];
    smt.insert(key_b, value_b);

    // --- insert a value with the same 32-bit prefix into the tree -----------
    let smt2 = smt.clone();
    let raw_c = 0b_01010101_01010101_11111111_11111111_11111101_10101010_10111100_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    let value_c = [ONE, ONE, ZERO, ZERO];
    smt.insert(key_c, value_c);

    let smt3 = smt.clone();
    let raw_d = 0b_01010101_01010101_11111111_11111111_10110101_10101010_11111100_00000000_u64;
    let key_d = RpoDigest::from([ZERO, ZERO, ONE, Felt::new(raw_d)]);
    let value_d = [ONE, ZERO, ZERO, ZERO];
    smt.insert(key_d, value_d);

    // --- delete the last inserted value -------------------------------------
    assert_eq!(smt.insert(key_d, EMPTY_WORD), value_d);
    assert_eq!(smt, smt3);

    assert_eq!(smt.insert(key_c, EMPTY_WORD), value_c);
    assert_eq!(smt, smt2);

    assert_eq!(smt.insert(key_b, EMPTY_WORD), value_b);
    assert_eq!(smt, smt1);

    assert_eq!(smt.insert(key_a, EMPTY_WORD), value_a);
    assert_eq!(smt, smt0);
}

#[test]
fn tsmt_delete_64_leaf_promotion() {
    let mut smt = TieredSmt::default();

    // --- delete from bottom tier (no promotion to upper tiers) --------------

    // insert a value into the tree
    let raw_a = 0b_01010101_01010101_11111111_11111111_10101010_10101010_11111111_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let value_a = [ONE, ONE, ONE, ONE];
    smt.insert(key_a, value_a);

    // insert another value with a key having the same 64-bit prefix
    let key_b = RpoDigest::from([ONE, ONE, ZERO, Felt::new(raw_a)]);
    let value_b = [ONE, ONE, ONE, ZERO];
    smt.insert(key_b, value_b);

    // insert a value with a key which shared the same 48-bit prefix
    let raw_c = 0b_01010101_01010101_11111111_11111111_10101010_10101010_00111111_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    let value_c = [ONE, ONE, ZERO, ZERO];
    smt.insert(key_c, value_c);

    // delete entry A and compare to the tree which was built from B and C
    smt.insert(key_a, EMPTY_WORD);

    let mut expected_smt = TieredSmt::default();
    expected_smt.insert(key_b, value_b);
    expected_smt.insert(key_c, value_c);
    assert_eq!(smt, expected_smt);

    // entries B and C should stay at depth 64
    assert_eq!(smt.nodes.get_leaf_index(&key_b).0.depth(), 64);
    assert_eq!(smt.nodes.get_leaf_index(&key_c).0.depth(), 64);

    // --- delete from bottom tier (promotion to depth 48) --------------------

    let mut smt = TieredSmt::default();
    smt.insert(key_a, value_a);
    smt.insert(key_b, value_b);

    // insert a value with a key which shared the same 32-bit prefix
    let raw_c = 0b_01010101_01010101_11111111_11111111_11101010_10101010_11111111_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    smt.insert(key_c, value_c);

    // delete entry A and compare to the tree which was built from B and C
    smt.insert(key_a, EMPTY_WORD);

    let mut expected_smt = TieredSmt::default();
    expected_smt.insert(key_b, value_b);
    expected_smt.insert(key_c, value_c);
    assert_eq!(smt, expected_smt);

    // entry B moves to depth 48, entry C stays at depth 48
    assert_eq!(smt.nodes.get_leaf_index(&key_b).0.depth(), 48);
    assert_eq!(smt.nodes.get_leaf_index(&key_c).0.depth(), 48);

    // --- delete from bottom tier (promotion to depth 32) --------------------

    let mut smt = TieredSmt::default();
    smt.insert(key_a, value_a);
    smt.insert(key_b, value_b);

    // insert a value with a key which shared the same 16-bit prefix
    let raw_c = 0b_01010101_01010101_01111111_11111111_10101010_10101010_11111111_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    smt.insert(key_c, value_c);

    // delete entry A and compare to the tree which was built from B and C
    smt.insert(key_a, EMPTY_WORD);

    let mut expected_smt = TieredSmt::default();
    expected_smt.insert(key_b, value_b);
    expected_smt.insert(key_c, value_c);
    assert_eq!(smt, expected_smt);

    // entry B moves to depth 32, entry C stays at depth 32
    assert_eq!(smt.nodes.get_leaf_index(&key_b).0.depth(), 32);
    assert_eq!(smt.nodes.get_leaf_index(&key_c).0.depth(), 32);

    // --- delete from bottom tier (promotion to depth 16) --------------------

    let mut smt = TieredSmt::default();
    smt.insert(key_a, value_a);
    smt.insert(key_b, value_b);

    // insert a value with a key which shared prefix < 16 bits
    let raw_c = 0b_01010101_01010100_11111111_11111111_10101010_10101010_11111111_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    smt.insert(key_c, value_c);

    // delete entry A and compare to the tree which was built from B and C
    smt.insert(key_a, EMPTY_WORD);

    let mut expected_smt = TieredSmt::default();
    expected_smt.insert(key_b, value_b);
    expected_smt.insert(key_c, value_c);
    assert_eq!(smt, expected_smt);

    // entry B moves to depth 16, entry C stays at depth 16
    assert_eq!(smt.nodes.get_leaf_index(&key_b).0.depth(), 16);
    assert_eq!(smt.nodes.get_leaf_index(&key_c).0.depth(), 16);
}

#[test]
fn test_order_sensitivity() {
    let raw = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000001_u64;
    let value = [ONE; WORD_SIZE];

    let key_1 = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let key_2 = RpoDigest::from([ONE, ONE, ZERO, Felt::new(raw)]);

    let mut smt_1 = TieredSmt::default();

    smt_1.insert(key_1, value);
    smt_1.insert(key_2, value);
    smt_1.insert(key_2, EMPTY_WORD);

    let mut smt_2 = TieredSmt::default();
    smt_2.insert(key_1, value);

    assert_eq!(smt_1.root(), smt_2.root());
}

// BOTTOM TIER TESTS
// ================================================================================================

#[test]
fn tsmt_bottom_tier() {
    let mut smt = TieredSmt::default();
    let mut store = MerkleStore::default();

    // common prefix for the keys
    let prefix = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;

    // --- insert the first value ---------------------------------------------
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(prefix)]);
    let val_a = [ONE; WORD_SIZE];
    smt.insert(key_a, val_a);

    // --- insert the second value --------------------------------------------
    // this key has the same 64-bit prefix and thus both values should end up in the same
    // node at depth 64
    let key_b = RpoDigest::from([ZERO, ONE, ONE, Felt::new(prefix)]);
    let val_b = [Felt::new(2); WORD_SIZE];
    smt.insert(key_b, val_b);

    // --- build Merkle store with equivalent data ----------------------------
    let index = NodeIndex::make(64, prefix);
    // to build bottom leaf we sort by key starting with the least significant element, thus
    // key_b is smaller than key_a.
    let leaf_node = build_bottom_leaf_node(&[key_b, key_a], &[val_b, val_a]);
    let mut tree_root = get_init_root();
    tree_root = store.set_node(tree_root, index, leaf_node).unwrap().root;

    // --- verify that data is consistent between store and tree --------------

    assert_eq!(smt.root(), tree_root);

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_value(key_b), val_b);

    assert_eq!(smt.get_node(index).unwrap(), leaf_node);
    let expected_path = store.get_path(tree_root, index).unwrap().path;
    assert_eq!(smt.get_path(index).unwrap(), expected_path);

    // make sure inner nodes match - the store contains more entries because it keeps track of
    // all prior state - so, we don't check that the number of inner nodes is the same in both
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));

    // make sure leaves are returned correctly
    let smt_clone = smt.clone();
    let mut leaves = smt_clone.bottom_leaves();
    assert_eq!(leaves.next(), Some((leaf_node, vec![(key_b, val_b), (key_a, val_a)])));
    assert_eq!(leaves.next(), None);

    // --- update a leaf at the bottom tier -------------------------------------------------------

    let val_a2 = [Felt::new(3); WORD_SIZE];
    assert_eq!(smt.insert(key_a, val_a2), val_a);

    let leaf_node = build_bottom_leaf_node(&[key_b, key_a], &[val_b, val_a2]);
    store.set_node(tree_root, index, leaf_node).unwrap();

    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));

    let mut leaves = smt.bottom_leaves();
    assert_eq!(leaves.next(), Some((leaf_node, vec![(key_b, val_b), (key_a, val_a2)])));
    assert_eq!(leaves.next(), None);
}

#[test]
fn tsmt_bottom_tier_two() {
    let mut smt = TieredSmt::default();
    let mut store = MerkleStore::default();

    // --- insert the first value ---------------------------------------------
    let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let val_a = [ONE; WORD_SIZE];
    smt.insert(key_a, val_a);

    // --- insert the second value --------------------------------------------
    // the key for this value has the same 48-bit prefix as the key for the first value,
    // thus, on insertions, both should end up in different nodes at depth 64
    let raw_b = 0b_10101010_10101010_00011111_11111111_10010110_10010011_01100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let val_b = [Felt::new(2); WORD_SIZE];
    smt.insert(key_b, val_b);

    // --- build Merkle store with equivalent data ----------------------------
    let mut tree_root = get_init_root();
    let index_a = NodeIndex::make(64, raw_a);
    let leaf_node_a = build_bottom_leaf_node(&[key_a], &[val_a]);
    tree_root = store.set_node(tree_root, index_a, leaf_node_a).unwrap().root;

    let index_b = NodeIndex::make(64, raw_b);
    let leaf_node_b = build_bottom_leaf_node(&[key_b], &[val_b]);
    tree_root = store.set_node(tree_root, index_b, leaf_node_b).unwrap().root;

    // --- verify that data is consistent between store and tree --------------

    assert_eq!(smt.root(), tree_root);

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root, index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root, index_b).unwrap().path;
    assert_eq!(smt.get_path(index_b).unwrap(), expected_path);

    // make sure inner nodes match - the store contains more entries because it keeps track of
    // all prior state - so, we don't check that the number of inner nodes is the same in both
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));

    // make sure leaves are returned correctly
    let mut leaves = smt.bottom_leaves();
    assert_eq!(leaves.next(), Some((leaf_node_b, vec![(key_b, val_b)])));
    assert_eq!(leaves.next(), Some((leaf_node_a, vec![(key_a, val_a)])));
    assert_eq!(leaves.next(), None);
}

// GET PROOF TESTS
// ================================================================================================

#[test]
fn tsmt_get_proof() {
    let mut smt = TieredSmt::default();

    // --- insert a value into the tree ---------------------------------------
    let raw_a = 0b_01010101_01010101_11111111_11111111_10110101_10101010_11111100_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let value_a = [ONE, ONE, ONE, ONE];
    smt.insert(key_a, value_a);

    // --- insert a value with the same 48-bit prefix into the tree -----------
    let raw_b = 0b_01010101_01010101_11111111_11111111_10110101_10101010_10111100_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let value_b = [ONE, ONE, ONE, ZERO];
    smt.insert(key_b, value_b);

    let smt_alt = smt.clone();

    // --- insert a value with the same 32-bit prefix into the tree -----------
    let raw_c = 0b_01010101_01010101_11111111_11111111_11111101_10101010_10111100_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    let value_c = [ONE, ONE, ZERO, ZERO];
    smt.insert(key_c, value_c);

    // --- insert a value with the same 64-bit prefix as A into the tree ------
    let raw_d = 0b_01010101_01010101_11111111_11111111_10110101_10101010_11111100_00000000_u64;
    let key_d = RpoDigest::from([ZERO, ZERO, ONE, Felt::new(raw_d)]);
    let value_d = [ONE, ZERO, ZERO, ZERO];
    smt.insert(key_d, value_d);

    // at this point the tree looks as follows:
    // - A and D are located in the same node at depth 64.
    // - B is located at depth 64 and shares the same 48-bit prefix with A and D.
    // - C is located at depth 48 and shares the same 32-bit prefix with A, B, and D.

    // --- generate proof for key A and test that it verifies correctly -------
    let proof = smt.prove(key_a);
    assert!(proof.verify_membership(&key_a, &value_a, &smt.root()));

    assert!(!proof.verify_membership(&key_a, &value_b, &smt.root()));
    assert!(!proof.verify_membership(&key_a, &EMPTY_WORD, &smt.root()));
    assert!(!proof.verify_membership(&key_b, &value_a, &smt.root()));
    assert!(!proof.verify_membership(&key_a, &value_a, &smt_alt.root()));

    assert_eq!(proof.get(&key_a), Some(value_a));
    assert_eq!(proof.get(&key_b), None);

    // since A and D are stored in the same node, we should be able to use the proof to verify
    // membership of D
    assert!(proof.verify_membership(&key_d, &value_d, &smt.root()));
    assert_eq!(proof.get(&key_d), Some(value_d));

    // --- generate proof for key B and test that it verifies correctly -------
    let proof = smt.prove(key_b);
    assert!(proof.verify_membership(&key_b, &value_b, &smt.root()));

    assert!(!proof.verify_membership(&key_b, &value_a, &smt.root()));
    assert!(!proof.verify_membership(&key_b, &EMPTY_WORD, &smt.root()));
    assert!(!proof.verify_membership(&key_a, &value_b, &smt.root()));
    assert!(!proof.verify_membership(&key_b, &value_b, &smt_alt.root()));

    assert_eq!(proof.get(&key_b), Some(value_b));
    assert_eq!(proof.get(&key_a), None);

    // --- generate proof for key C and test that it verifies correctly -------
    let proof = smt.prove(key_c);
    assert!(proof.verify_membership(&key_c, &value_c, &smt.root()));

    assert!(!proof.verify_membership(&key_c, &value_a, &smt.root()));
    assert!(!proof.verify_membership(&key_c, &EMPTY_WORD, &smt.root()));
    assert!(!proof.verify_membership(&key_a, &value_c, &smt.root()));
    assert!(!proof.verify_membership(&key_c, &value_c, &smt_alt.root()));

    assert_eq!(proof.get(&key_c), Some(value_c));
    assert_eq!(proof.get(&key_b), None);

    // --- generate proof for key D and test that it verifies correctly -------
    let proof = smt.prove(key_d);
    assert!(proof.verify_membership(&key_d, &value_d, &smt.root()));

    assert!(!proof.verify_membership(&key_d, &value_b, &smt.root()));
    assert!(!proof.verify_membership(&key_d, &EMPTY_WORD, &smt.root()));
    assert!(!proof.verify_membership(&key_b, &value_d, &smt.root()));
    assert!(!proof.verify_membership(&key_d, &value_d, &smt_alt.root()));

    assert_eq!(proof.get(&key_d), Some(value_d));
    assert_eq!(proof.get(&key_b), None);

    // since A and D are stored in the same node, we should be able to use the proof to verify
    // membership of A
    assert!(proof.verify_membership(&key_a, &value_a, &smt.root()));
    assert_eq!(proof.get(&key_a), Some(value_a));

    // --- generate proof for an empty key at depth 64 ------------------------
    // this key has the same 48-bit prefix as A but is different from B
    let raw = 0b_01010101_01010101_11111111_11111111_10110101_10101010_11111100_00000011_u64;
    let key = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);

    let proof = smt.prove(key);
    assert!(proof.verify_membership(&key, &EMPTY_WORD, &smt.root()));

    assert!(!proof.verify_membership(&key, &value_a, &smt.root()));
    assert!(!proof.verify_membership(&key, &EMPTY_WORD, &smt_alt.root()));

    assert_eq!(proof.get(&key), Some(EMPTY_WORD));
    assert_eq!(proof.get(&key_b), None);

    // the same proof should verify against any key with the same 64-bit prefix
    let key2 = RpoDigest::from([ONE, ONE, ZERO, Felt::new(raw)]);
    assert!(proof.verify_membership(&key2, &EMPTY_WORD, &smt.root()));
    assert_eq!(proof.get(&key2), Some(EMPTY_WORD));

    // but verifying if against a key with the same 63-bit prefix (or smaller) should fail
    let raw3 = 0b_01010101_01010101_11111111_11111111_10110101_10101010_11111100_00000010_u64;
    let key3 = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw3)]);
    assert!(!proof.verify_membership(&key3, &EMPTY_WORD, &smt.root()));
    assert_eq!(proof.get(&key3), None);

    // --- generate proof for an empty key at depth 48 ------------------------
    // this key has the same 32-prefix as A, B, C, and D, but is different from C
    let raw = 0b_01010101_01010101_11111111_11111111_00110101_10101010_11111100_00000000_u64;
    let key = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);

    let proof = smt.prove(key);
    assert!(proof.verify_membership(&key, &EMPTY_WORD, &smt.root()));

    assert!(!proof.verify_membership(&key, &value_a, &smt.root()));
    assert!(!proof.verify_membership(&key, &EMPTY_WORD, &smt_alt.root()));

    assert_eq!(proof.get(&key), Some(EMPTY_WORD));
    assert_eq!(proof.get(&key_b), None);

    // the same proof should verify against any key with the same 48-bit prefix
    let raw2 = 0b_01010101_01010101_11111111_11111111_00110101_10101010_01111100_00000000_u64;
    let key2 = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw2)]);
    assert!(proof.verify_membership(&key2, &EMPTY_WORD, &smt.root()));
    assert_eq!(proof.get(&key2), Some(EMPTY_WORD));

    // but verifying against a key with the same 47-bit prefix (or smaller) should fail
    let raw3 = 0b_01010101_01010101_11111111_11111111_00110101_10101011_11111100_00000000_u64;
    let key3 = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw3)]);
    assert!(!proof.verify_membership(&key3, &EMPTY_WORD, &smt.root()));
    assert_eq!(proof.get(&key3), None);
}

// ERROR TESTS
// ================================================================================================

#[test]
fn tsmt_node_not_available() {
    let mut smt = TieredSmt::default();

    let raw = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let value = [ONE; WORD_SIZE];

    // build an index which is just below the inserted leaf node
    let index = NodeIndex::make(17, raw >> 47);

    // since we haven't inserted the node yet, we should be able to get node and path to this index
    assert!(smt.get_node(index).is_ok());
    assert!(smt.get_path(index).is_ok());

    smt.insert(key, value);

    // but once the node is inserted, everything under it should be unavailable
    assert!(smt.get_node(index).is_err());
    assert!(smt.get_path(index).is_err());

    let index = NodeIndex::make(32, raw >> 32);
    assert!(smt.get_node(index).is_err());
    assert!(smt.get_path(index).is_err());

    let index = NodeIndex::make(34, raw >> 30);
    assert!(smt.get_node(index).is_err());
    assert!(smt.get_path(index).is_err());

    let index = NodeIndex::make(50, raw >> 14);
    assert!(smt.get_node(index).is_err());
    assert!(smt.get_path(index).is_err());

    let index = NodeIndex::make(64, raw);
    assert!(smt.get_node(index).is_err());
    assert!(smt.get_path(index).is_err());
}

// HELPER FUNCTIONS
// ================================================================================================

fn get_init_root() -> RpoDigest {
    EmptySubtreeRoots::empty_hashes(64)[0]
}

fn build_leaf_node(key: RpoDigest, value: Word, depth: u8) -> RpoDigest {
    Rpo256::merge_in_domain(&[key, value.into()], depth.into())
}

fn build_bottom_leaf_node(keys: &[RpoDigest], values: &[Word]) -> RpoDigest {
    assert_eq!(keys.len(), values.len());

    let mut elements = Vec::with_capacity(keys.len());
    for (key, val) in keys.iter().zip(values.iter()) {
        elements.extend_from_slice(key.as_elements());
        elements.extend_from_slice(val.as_slice());
    }

    Rpo256::hash_elements(&elements)
}

fn get_non_empty_nodes(store: &MerkleStore) -> Vec<InnerNodeInfo> {
    store
        .inner_nodes()
        .filter(|node| !is_empty_subtree(&node.value))
        .collect::<Vec<_>>()
}

fn is_empty_subtree(node: &RpoDigest) -> bool {
    EmptySubtreeRoots::empty_hashes(255).contains(node)
}
