use super::{
    super::{int_to_node, MerkleStore, MerkleTree, NodeIndex, PartialMerkleTree},
    Word,
};

// TEST DATA
// ================================================================================================

const NODE10: NodeIndex = NodeIndex::new_unchecked(1, 0);

const NODE22: NodeIndex = NodeIndex::new_unchecked(2, 2);

const NODE32: NodeIndex = NodeIndex::new_unchecked(3, 2);
const NODE33: NodeIndex = NodeIndex::new_unchecked(3, 3);

const VALUES8: [Word; 8] = [
    int_to_node(1),
    int_to_node(2),
    int_to_node(3),
    int_to_node(4),
    int_to_node(5),
    int_to_node(6),
    int_to_node(7),
    int_to_node(8),
];

// TESTS
// ================================================================================================

// with_paths CONSTRUCTOR TESTS
// ------------------------------------------------------------------------------------------------

#[test]
fn get_root() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3_u64, path33.value.into(), path33.path)]).unwrap();

    assert_eq!(pmt.root(), expected_root.into());
}

#[test]
fn add_and_get_paths() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let expected_path33 = ms.get_path(expected_root, NODE33).unwrap();
    let expected_path22 = ms.get_path(expected_root, NODE22).unwrap();

    let pmt = PartialMerkleTree::with_paths([
        (3_u64, expected_path33.value.into(), expected_path33.path.clone()),
        (2, expected_path22.value.into(), expected_path22.path.clone()),
    ])
    .unwrap();

    let path33 = pmt.get_path(NODE33).unwrap();
    let path22 = pmt.get_path(NODE22).unwrap();

    assert_eq!(expected_path33.path, path33);
    assert_eq!(expected_path22.path, path22);
}

#[test]
fn get_node() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3_u64, path33.value.into(), path33.path)]).unwrap();

    assert_eq!(ms.get_node(expected_root, NODE32).unwrap(), *pmt.get_node(NODE32).unwrap());
    assert_eq!(ms.get_node(expected_root, NODE10).unwrap(), *pmt.get_node(NODE10).unwrap());
}

#[test]
fn update_leaf() {
    let mut mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let root = mt.root();

    let ms = MerkleStore::from(&mt);
    let path33 = ms.get_path(root, NODE33).unwrap();

    let mut pmt =
        PartialMerkleTree::with_paths([(3_u64, path33.value.into(), path33.path)]).unwrap();

    let new_value32 = int_to_node(132);
    mt.update_leaf(2_u64, new_value32).unwrap();
    let expected_root = mt.root();

    pmt.update_leaf(NODE32, new_value32.into()).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, *actual_root);
}

#[test]
fn check_leaf_depth() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3_u64, path33.value.into(), path33.path)]).unwrap();

    assert_eq!(pmt.get_leaf_depth(0), 2);
    assert_eq!(pmt.get_leaf_depth(1), 2);
    assert_eq!(pmt.get_leaf_depth(2), 3);
    assert_eq!(pmt.get_leaf_depth(3), 3);
    assert_eq!(pmt.get_leaf_depth(4), 1);
    assert_eq!(pmt.get_leaf_depth(5), 1);
    assert_eq!(pmt.get_leaf_depth(6), 1);
    assert_eq!(pmt.get_leaf_depth(7), 1);
}

// TODO: add test for add_path function and check correctness of leaf determination (requires
// inner_nodes iter)
