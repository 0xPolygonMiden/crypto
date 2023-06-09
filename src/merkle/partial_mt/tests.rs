use super::{
    super::{int_to_node, MerkleStore, MerkleTree, NodeIndex, PartialMerkleTree},
    Rpo256, ValuePath, Vec, Word,
};

// TEST DATA
// ================================================================================================

const NODE10: NodeIndex = NodeIndex::new_unchecked(1, 0);
const NODE11: NodeIndex = NodeIndex::new_unchecked(1, 1);

const NODE20: NodeIndex = NodeIndex::new_unchecked(2, 0);
const NODE22: NodeIndex = NodeIndex::new_unchecked(2, 2);
const NODE23: NodeIndex = NodeIndex::new_unchecked(2, 3);

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

    let pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    assert_eq!(pmt.root(), expected_root.into());
}

#[test]
fn add_and_get_paths() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let expected_path33 = ms.get_path(expected_root, NODE33).unwrap();
    let expected_path22 = ms.get_path(expected_root, NODE22).unwrap();

    let mut pmt = PartialMerkleTree::new();
    pmt.add_path(3, expected_path33.value.into(), expected_path33.path.clone())
        .unwrap();
    pmt.add_path(2, expected_path22.value.into(), expected_path22.path.clone())
        .unwrap();

    let path33 = pmt.get_path(NODE33).unwrap();
    let path22 = pmt.get_path(NODE22).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_path33.path, path33);
    assert_eq!(expected_path22.path, path22);
    assert_eq!(expected_root, *actual_root);
}

#[test]
fn get_node() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    assert_eq!(ms.get_node(expected_root, NODE32).unwrap(), *pmt.get_node(NODE32).unwrap());
    assert_eq!(ms.get_node(expected_root, NODE10).unwrap(), *pmt.get_node(NODE10).unwrap());
}

#[test]
fn update_leaf() {
    let mut mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let root = mt.root();

    let ms = MerkleStore::from(&mt);
    let path33 = ms.get_path(root, NODE33).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    let new_value32 = int_to_node(132);
    mt.update_leaf(2, new_value32).unwrap();
    let expected_root = mt.root();

    pmt.update_leaf(NODE32, new_value32.into()).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, *actual_root);

    let mut new_vals = VALUES8.clone();
    new_vals[1] = int_to_node(131);
    new_vals[2] = int_to_node(132);
    let new_value20 = Rpo256::merge(&[new_vals[0].into(), new_vals[1].into()]);
    let mt = MerkleTree::new(new_vals.to_vec()).unwrap();
    let expected_root = mt.root();

    pmt.update_leaf(NODE20, new_value20).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, *actual_root);
}

#[test]
fn check_leaf_depth() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(4, 1)), 2);
    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(4, 6)), 3);
    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(4, 10)), 1);

    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(3, 1)), 2);
    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(3, 2)), 3);
    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(3, 5)), 1);
    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(3, 7)), 1);

    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(2, 0)), 2);
    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(2, 1)), 0);
    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(2, 2)), 1);
    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(2, 3)), 1);

    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(1, 0)), 0);
    assert_eq!(pmt.get_leaf_depth(NodeIndex::make(1, 1)), 1);
}

#[test]
fn get_paths() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();
    let path22 = ms.get_path(expected_root, NODE22).unwrap();

    let mut pmt = PartialMerkleTree::new();
    pmt.add_path(3, path33.value.into(), path33.path.clone()).unwrap();
    pmt.add_path(2, path22.value.into(), path22.path.clone()).unwrap();

    let leaves = vec![NODE20, NODE22, NODE23, NODE32, NODE33];
    let expected_paths: Vec<(NodeIndex, ValuePath)> = leaves
        .iter()
        .map(|&leaf| {
            (
                leaf,
                ValuePath {
                    value: mt.get_node(leaf).unwrap().into(),
                    path: mt.get_path(leaf).unwrap(),
                },
            )
        })
        .collect();

    let actual_paths = pmt.paths();

    assert_eq!(expected_paths, actual_paths);
}

#[test]
fn leaves() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();
    let path22 = ms.get_path(expected_root, NODE22).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    let value11 = mt.get_node(NODE11).unwrap().into();
    let value20 = mt.get_node(NODE20).unwrap().into();
    let value32 = mt.get_node(NODE32).unwrap().into();
    let value33 = mt.get_node(NODE33).unwrap().into();

    let leaves = vec![(NODE11, value11), (NODE20, value20), (NODE32, value32), (NODE33, value33)];

    let expected_leaves = leaves.iter().map(|&tuple| tuple);
    assert!(expected_leaves.eq(pmt.leaves()));

    pmt.add_path(2, path22.value.into(), path22.path).unwrap();

    let value20 = mt.get_node(NODE20).unwrap().into();
    let value22 = mt.get_node(NODE22).unwrap().into();
    let value23 = mt.get_node(NODE23).unwrap().into();
    let value32 = mt.get_node(NODE32).unwrap().into();
    let value33 = mt.get_node(NODE33).unwrap().into();

    let leaves = vec![
        (NODE20, value20),
        (NODE22, value22),
        (NODE23, value23),
        (NODE32, value32),
        (NODE33, value33),
    ];

    let expected_leaves = leaves.iter().map(|&tuple| tuple);
    assert!(expected_leaves.eq(pmt.leaves()));
}
