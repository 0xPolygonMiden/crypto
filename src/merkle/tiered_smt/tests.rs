use super::*;

#[test]
fn insert_to_correct_tree_index_single_leaf() {
    let storage = Storage::default();
    let tree = TieredSmt::with_storage(storage);

    let key = 0b_01010000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_u64;
    let key = Felt::from_mont(key);
    let key = RpoDigest::new([key; 4]);

    let depth = 4;
    let index = 5;
    let index = TreeIndex::new(depth, index);

    // first, test the correctness of the tree index implementation
    let traversed = TreeIndex::root()
        .traverse(false)
        .traverse(true)
        .traverse(false)
        .traverse(true);
    assert_eq!(index, traversed);

    // then, test the correctness of the bits iterator
    let mut bits = BitsIterator::from(&key);
    let traversed = BitsIterator::traverse(TreeIndex::root(), bits.by_ref()).unwrap();
    assert_eq!(index, traversed);

    // append a message with arbitrary key
    let message = b"\"We speak different languages, as usual\", responded Woland, \"but this does not change the things we speak about\"";
    let message = Rpo256::hash(message);
    let inserted = tree.insert_with_key(key, &message).unwrap();
    assert_eq!(key, inserted);

    // check the node is inserted in the correct position
    let r#type = tree.peek_node_type(&index).unwrap();
    assert_eq!(ContentType::Leaf, r#type);
}

#[test]
fn insert_to_correct_tree_index_multiple_leaves() {
    let storage = Storage::default();
    let tree = TieredSmt::with_storage(storage);

    let key_a = 0b_10011101_00000000_00000000_00000000_00000000_00000000_00000000_00000000_u64;
    let key_a = Felt::from_mont(key_a);
    let key_a = RpoDigest::new([key_a; 4]);

    let depth_a = 8;
    let index_a = 157;
    let index_a = TreeIndex::new(depth_a, index_a);

    let key_b = 0b_10010110_00000000_00000000_00000000_00000000_00000000_00000000_00000000_u64;
    let key_b = Felt::from_mont(key_b);
    let key_b = RpoDigest::new([key_b; 4]);

    let depth_b = 8;
    let index_b = 150;
    let index_b = TreeIndex::new(depth_b, index_b);

    // first, test the correctness of the tree index implementation
    let traversed = TreeIndex::root()
        .traverse(true)
        .traverse(false)
        .traverse(false)
        .traverse(true)
        .traverse(false)
        .traverse(true)
        .traverse(true)
        .traverse(false);
    assert_eq!(index_b, traversed);

    let traversed = TreeIndex::root()
        .traverse(true)
        .traverse(false)
        .traverse(false)
        .traverse(true)
        .traverse(true)
        .traverse(true)
        .traverse(false)
        .traverse(true);
    assert_eq!(index_a, traversed);

    // then, test the correctness of the bits iterator
    let mut bits_a = BitsIterator::from(&key_a);
    let traversed = BitsIterator::traverse(TreeIndex::root(), bits_a.by_ref()).unwrap();
    let traversed = BitsIterator::traverse(traversed, bits_a.by_ref()).unwrap();
    assert_eq!(index_a, traversed);

    let mut bits_b = BitsIterator::from(&key_b);
    let traversed = BitsIterator::traverse(TreeIndex::root(), bits_b.by_ref()).unwrap();
    let traversed = BitsIterator::traverse(traversed, bits_b.by_ref()).unwrap();
    assert_eq!(index_b, traversed);

    // append a message with arbitrary key
    let message_a = b"Poets have been mysteriously silent on the subject of cheese...";
    let message_a = Rpo256::hash(message_a);
    let inserted_a = tree.insert_with_key(key_a, &message_a).unwrap();
    assert_eq!(key_a, inserted_a);

    // check the node is inserted in the correct position
    let index_a_reversed = (0..TieredSmt::TIER_DEPTH).fold(index_a, |idx, _| idx.reverse());
    let r#type = tree.peek_node_type(&index_a_reversed).unwrap();
    assert_eq!(ContentType::Leaf, r#type);

    // append another message with arbitrary key that will lead to the same node of the previous
    // message, generating a sub-tree.
    let message_b = b"Awake, arise or be for ever fall'n.";
    let message_b = Rpo256::hash(message_b);
    let inserted_b = tree.insert_with_key(key_b, &message_b).unwrap();
    assert_eq!(key_b, inserted_b);

    // the previous message index should now be an internal node as it was replaced by a sub-tree
    let r#type = tree.peek_node_type(&index_a_reversed).unwrap();
    assert_eq!(ContentType::Internal, r#type);

    // the final positions should match as leaf
    let r#type = tree.peek_node_type(&index_a).unwrap();
    assert_eq!(ContentType::Leaf, r#type);
    let r#type = tree.peek_node_type(&index_b).unwrap();
    assert_eq!(ContentType::Leaf, r#type);
}
