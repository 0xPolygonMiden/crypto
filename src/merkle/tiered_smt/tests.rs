use super::{
    super::{super::ONE, Felt, MerkleStore, WORD_SIZE, ZERO},
    get_remaining_path, EmptySubtreeRoots, InnerNodeInfo, NodeIndex, Rpo256, RpoDigest, TieredSmt,
    Vec, Word,
};

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

    assert_eq!(smt.root(), tree_root.into());

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

    assert_eq!(smt.root(), tree_root.into());

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root.into(), index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root.into(), index_b).unwrap().path;
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

    assert_eq!(smt.root(), tree_root.into());

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root.into(), index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root.into(), index_b).unwrap().path;
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

    assert_eq!(smt.root(), tree_root.into());

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root.into(), index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root.into(), index_b).unwrap().path;
    assert_eq!(smt.get_path(index_b).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_c), val_c);
    assert_eq!(smt.get_node(index_c).unwrap(), leaf_node_c);
    let expected_path = store.get_path(tree_root.into(), index_c).unwrap().path;
    assert_eq!(smt.get_path(index_c).unwrap(), expected_path);

    // make sure inner nodes match - the store contains more entries because it keeps track of
    // all prior state - so, we don't check that the number of inner nodes is the same in both
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));
}

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

    assert_eq!(smt.root(), tree_root.into());

    assert_eq!(smt.get_value(key), value_b);
    assert_eq!(smt.get_node(index).unwrap(), leaf_node);
    let expected_path = store.get_path(tree_root.into(), index).unwrap().path;
    assert_eq!(smt.get_path(index).unwrap(), expected_path);

    // make sure inner nodes match - the store contains more entries because it keeps track of
    // all prior state - so, we don't check that the number of inner nodes is the same in both
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));
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

    assert_eq!(smt.root(), tree_root.into());

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_value(key_b), val_b);

    assert_eq!(smt.get_node(index).unwrap(), leaf_node);
    let expected_path = store.get_path(tree_root.into(), index).unwrap().path;
    assert_eq!(smt.get_path(index).unwrap(), expected_path);

    // make sure inner nodes match - the store contains more entries because it keeps track of
    // all prior state - so, we don't check that the number of inner nodes is the same in both
    let expected_nodes = get_non_empty_nodes(&store);
    let actual_nodes = smt.inner_nodes().collect::<Vec<_>>();
    actual_nodes.iter().for_each(|node| assert!(expected_nodes.contains(node)));

    // make sure leaves are returned correctly
    let mut leaves = smt.bottom_leaves();
    assert_eq!(leaves.next(), Some((leaf_node, vec![(key_b, val_b), (key_a, val_a)])));
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

    assert_eq!(smt.root(), tree_root.into());

    assert_eq!(smt.get_value(key_a), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root.into(), index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root.into(), index_b).unwrap().path;
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
    let remaining_path = get_remaining_path(key, depth as u32);
    Rpo256::merge_in_domain(&[remaining_path, value.into()], depth.into())
}

fn build_bottom_leaf_node(keys: &[RpoDigest], values: &[Word]) -> RpoDigest {
    assert_eq!(keys.len(), values.len());

    let mut elements = Vec::with_capacity(keys.len());
    for (key, val) in keys.iter().zip(values.iter()) {
        let mut key = Word::from(key);
        key[3] = ZERO;
        elements.extend_from_slice(&key);
        elements.extend_from_slice(val.as_slice());
    }

    Rpo256::hash_elements(&elements)
}

fn get_non_empty_nodes(store: &MerkleStore) -> Vec<InnerNodeInfo> {
    store
        .inner_nodes()
        .filter(|node| !is_empty_subtree(&RpoDigest::from(node.value)))
        .collect::<Vec<_>>()
}

fn is_empty_subtree(node: &RpoDigest) -> bool {
    EmptySubtreeRoots::empty_hashes(255).contains(&node)
}
