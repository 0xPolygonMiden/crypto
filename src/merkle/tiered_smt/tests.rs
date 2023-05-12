use super::{
    super::{super::ONE, Felt, MerkleStore, WORD_SIZE},
    get_remaining_path, EmptySubtreeRoots, NodeIndex, Rpo256, RpoDigest, TieredSmt, Word,
};

#[test]
fn tsmt_insert_one() {
    let mut smt = TieredSmt::new();
    let mut store = MerkleStore::default();

    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let value = [ONE; WORD_SIZE];

    // since the tree is empty, the first node will be inserted at depth 16 and the index will be
    // 16 most significant bits of the key
    let index = NodeIndex::make(16, raw >> 48);
    let leaf_node = compute_leaf_node(key, value, 16);
    let tree_root = store.set_node(smt.root().into(), index, leaf_node.into()).unwrap().root;

    smt.insert(key, value).unwrap();

    assert_eq!(smt.root(), tree_root.into());

    // make sure the value was inserted, and the node is at the expected index
    assert_eq!(smt.get_value(key).unwrap(), value);
    assert_eq!(smt.get_node(index).unwrap(), leaf_node);

    // make sure the paths we get from the store and the tree match
    let expected_path = store.get_path(tree_root, index).unwrap();
    assert_eq!(smt.get_path(index).unwrap(), expected_path.path);
}

#[test]
fn tsmt_insert_two() {
    let mut smt = TieredSmt::new();
    let mut store = MerkleStore::default();

    // --- insert the first value ---------------------------------------------
    let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let val_a = [ONE; WORD_SIZE];
    smt.insert(key_a, val_a).unwrap();

    // --- insert the second value --------------------------------------------
    // the key for this value has the same 16-bit prefix as the key for the first value,
    // thus, on insertions, both values should be pushed to depth 32 tier
    let raw_b = 0b_10101010_10101010_10011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let val_b = [Felt::new(2); WORD_SIZE];
    smt.insert(key_b, val_b).unwrap();

    // --- build Merkle store with equivalent data ----------------------------
    let mut tree_root = get_init_root();
    let index_a = NodeIndex::make(32, raw_a >> 32);
    let leaf_node_a = compute_leaf_node(key_a, val_a, 32);
    tree_root = store.set_node(tree_root, index_a, leaf_node_a.into()).unwrap().root;

    let index_b = NodeIndex::make(32, raw_b >> 32);
    let leaf_node_b = compute_leaf_node(key_b, val_b, 32);
    tree_root = store.set_node(tree_root, index_b, leaf_node_b.into()).unwrap().root;

    // --- verify that data is consistent between store and tree --------------

    assert_eq!(smt.root(), tree_root.into());

    assert_eq!(smt.get_value(key_a).unwrap(), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root, index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b).unwrap(), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root, index_b).unwrap().path;
    assert_eq!(smt.get_path(index_b).unwrap(), expected_path);
}

#[test]
fn tsmt_insert_three() {
    let mut smt = TieredSmt::new();
    let mut store = MerkleStore::default();

    // --- insert the first value ---------------------------------------------
    let raw_a = 0b_10101010_10101010_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_a = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_a)]);
    let val_a = [ONE; WORD_SIZE];
    smt.insert(key_a, val_a).unwrap();

    // --- insert the second value --------------------------------------------
    // the key for this value has the same 16-bit prefix as the key for the first value,
    // thus, on insertions, both values should be pushed to depth 32 tier
    let raw_b = 0b_10101010_10101010_10011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_b = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_b)]);
    let val_b = [Felt::new(2); WORD_SIZE];
    smt.insert(key_b, val_b).unwrap();

    // --- insert the third value ---------------------------------------------
    // the key for this value has the same 16-bit prefix as the keys for the first two,
    // values; thus, on insertions, it will be inserted into depth 32 tier, but will not
    // affect locations of the other two values
    let raw_c = 0b_10101010_10101010_11011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key_c = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw_c)]);
    let val_c = [Felt::new(3); WORD_SIZE];
    smt.insert(key_c, val_c).unwrap();

    // --- build Merkle store with equivalent data ----------------------------
    let mut tree_root = get_init_root();
    let index_a = NodeIndex::make(32, raw_a >> 32);
    let leaf_node_a = compute_leaf_node(key_a, val_a, 32);
    tree_root = store.set_node(tree_root, index_a, leaf_node_a.into()).unwrap().root;

    let index_b = NodeIndex::make(32, raw_b >> 32);
    let leaf_node_b = compute_leaf_node(key_b, val_b, 32);
    tree_root = store.set_node(tree_root, index_b, leaf_node_b.into()).unwrap().root;

    let index_c = NodeIndex::make(32, raw_c >> 32);
    let leaf_node_c = compute_leaf_node(key_c, val_c, 32);
    tree_root = store.set_node(tree_root, index_c, leaf_node_c.into()).unwrap().root;

    // --- verify that data is consistent between store and tree --------------

    assert_eq!(smt.root(), tree_root.into());

    assert_eq!(smt.get_value(key_a).unwrap(), val_a);
    assert_eq!(smt.get_node(index_a).unwrap(), leaf_node_a);
    let expected_path = store.get_path(tree_root, index_a).unwrap().path;
    assert_eq!(smt.get_path(index_a).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_b).unwrap(), val_b);
    assert_eq!(smt.get_node(index_b).unwrap(), leaf_node_b);
    let expected_path = store.get_path(tree_root, index_b).unwrap().path;
    assert_eq!(smt.get_path(index_b).unwrap(), expected_path);

    assert_eq!(smt.get_value(key_c).unwrap(), val_c);
    assert_eq!(smt.get_node(index_c).unwrap(), leaf_node_c);
    let expected_path = store.get_path(tree_root, index_c).unwrap().path;
    assert_eq!(smt.get_path(index_c).unwrap(), expected_path);
}

#[test]
fn tsmt_update() {
    let mut smt = TieredSmt::new();
    let mut store = MerkleStore::default();

    // --- insert a value into the tree ---------------------------------------
    let raw = 0b_01101001_01101100_00011111_11111111_10010110_10010011_11100000_00000000_u64;
    let key = RpoDigest::from([ONE, ONE, ONE, Felt::new(raw)]);
    let value_a = [ONE; WORD_SIZE];
    smt.insert(key, value_a).unwrap();

    // --- update value ---------------------------------------
    let value_b = [Felt::new(2); WORD_SIZE];
    smt.insert(key, value_b).unwrap();

    // --- verify consistency -------------------------------------------------
    let mut tree_root = get_init_root();
    let index = NodeIndex::make(16, raw >> 48);
    let leaf_node = compute_leaf_node(key, value_b, 16);
    tree_root = store.set_node(tree_root, index, leaf_node.into()).unwrap().root;

    assert_eq!(smt.root(), tree_root.into());

    assert_eq!(smt.get_value(key).unwrap(), value_b);
    assert_eq!(smt.get_node(index).unwrap(), leaf_node);
    let expected_path = store.get_path(tree_root, index).unwrap().path;
    assert_eq!(smt.get_path(index).unwrap(), expected_path);
}

// HELPER FUNCTIONS
// ================================================================================================

fn get_init_root() -> Word {
    EmptySubtreeRoots::empty_hashes(64)[0].into()
}

fn compute_leaf_node(key: RpoDigest, value: Word, depth: u8) -> RpoDigest {
    let remaining_path = get_remaining_path(key, depth as u32);
    Rpo256::merge_in_domain(&[remaining_path, value.into()], depth.into())
}
