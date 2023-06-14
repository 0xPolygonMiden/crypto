use super::{
    super::{int_to_node, MerkleStore, MerkleTree, NodeIndex, PartialMerkleTree},
    ValuePath, Vec, Word,
};

// TEST DATA
// ================================================================================================

const NODE10: NodeIndex = NodeIndex::new_unchecked(1, 0);
const NODE11: NodeIndex = NodeIndex::new_unchecked(1, 1);

const NODE20: NodeIndex = NodeIndex::new_unchecked(2, 0);
const NODE22: NodeIndex = NodeIndex::new_unchecked(2, 2);
const NODE23: NodeIndex = NodeIndex::new_unchecked(2, 3);

const NODE30: NodeIndex = NodeIndex::new_unchecked(3, 0);
const NODE31: NodeIndex = NodeIndex::new_unchecked(3, 1);
const NODE32: NodeIndex = NodeIndex::new_unchecked(3, 2);
const NODE33: NodeIndex = NodeIndex::new_unchecked(3, 3);

const VALUES8: [Word; 8] = [
    int_to_node(30),
    int_to_node(31),
    int_to_node(32),
    int_to_node(33),
    int_to_node(34),
    int_to_node(35),
    int_to_node(36),
    int_to_node(37),
];

// TESTS
// ================================================================================================

// For the Partial Merkle Tree tests we will use parts of the Merkle Tree which full form is
// illustrated below:
//
//              __________ root __________
//             /                          \
//       ____ 10 ____                ____ 11 ____
//      /            \              /            \
//     20            21            22            23
//   /    \        /    \        /    \        /    \
// (30)  (31)    (32)  (33)    (34)  (35)    (36)  (37)
//
// Where node number is a concatenation of its depth and index. For example, node with
// NodeIndex(3, 5) will be labled as `35`. Leaves of the tree are shown as nodes with parenthesis
// (33).

/// Checks that root returned by `root()` function is equal to the expected one.
#[test]
fn get_root() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    assert_eq!(pmt.root(), expected_root.into());
}

/// This test checks correctness of the `add_path()` and `get_path()` functions. First it creates a
/// PMT using `add_path()` by adding Merkle Paths from node 33 and node 22 to the empty PMT. Then
/// it checks that paths returned by `get_path()` function are equal to the expected ones.
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

/// Checks that function `get_node` used on nodes 10 and 32 returns expected values.
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

/// Updates leaves of the PMT using `update_leaf()` function and checks that new root of the tree
/// is equal to the expected one.
#[test]
fn update_leaf() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let root = mt.root();

    let mut ms = MerkleStore::from(&mt);
    let path33 = ms.get_path(root, NODE33).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    let new_value32 = int_to_node(132);
    let expected_root = ms.set_node(root, NODE32, new_value32).unwrap().root;

    pmt.update_leaf(NODE32, new_value32.into()).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, *actual_root);

    let new_value20 = int_to_node(120);
    let expected_root = ms.set_node(expected_root, NODE20, new_value20).unwrap().root;

    pmt.update_leaf(NODE20, new_value20.into()).unwrap();
    let actual_root = pmt.root();

    assert_eq!(expected_root, *actual_root);
}

/// Checks that paths of the PMT returned by `paths()` function are equal to the expected ones.
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
    // After PMT creation with path33 (33; 32, 20, 11) and path22 (22; 23, 10) we will have this
    // tree:
    //
    //           ______root______
    //          /                \
    //      ___10___           ___11___
    //     /        \         /        \
    //   (20)       21      (22)      (23)
    //            /    \
    //          (32)  (33)
    //
    // Which have leaf nodes 20, 22, 23, 32 and 33. Hence overall we will have 5 paths -- one path
    // for each leaf.

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

// Checks correctness of leaves determination when using the `leaves()` function.
#[test]
fn leaves() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();
    let path22 = ms.get_path(expected_root, NODE22).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();
    // After PMT creation with path33 (33; 32, 20, 11) we will have this tree:
    //
    //           ______root______
    //          /                \
    //      ___10___            (11)
    //     /         \
    //   (20)        21
    //             /    \
    //           (32)  (33)
    //
    // Which have leaf nodes 11, 20, 32 and 33.

    let value11 = mt.get_node(NODE11).unwrap().into();
    let value20 = mt.get_node(NODE20).unwrap().into();
    let value32 = mt.get_node(NODE32).unwrap().into();
    let value33 = mt.get_node(NODE33).unwrap().into();

    let leaves = vec![(NODE11, value11), (NODE20, value20), (NODE32, value32), (NODE33, value33)];

    let expected_leaves = leaves.iter().map(|&tuple| tuple);
    assert!(expected_leaves.eq(pmt.leaves()));

    pmt.add_path(2, path22.value.into(), path22.path).unwrap();
    // After adding the path22 (22; 23, 10) to the existing PMT we will have this tree:
    //
    //           ______root______
    //          /                \
    //      ___10___           ___11___
    //     /        \         /        \
    //   (20)       21      (22)      (23)
    //            /    \
    //          (32)  (33)
    //
    // Which have leaf nodes 20, 22, 23, 32 and 33.

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

/// Checks that addition of the path with different root will cause an error.
#[test]
fn err_add_path() {
    let path33 = vec![int_to_node(1), int_to_node(2), int_to_node(3)].into();
    let path22 = vec![int_to_node(4), int_to_node(5)].into();

    let mut pmt = PartialMerkleTree::new();
    pmt.add_path(3, int_to_node(6).into(), path33).unwrap();

    assert!(pmt.add_path(2, int_to_node(7).into(), path22).is_err());
}

/// Checks that the request of the node which is not in the PMT will cause an error.
#[test]
fn err_get_node() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    assert!(pmt.get_node(NODE22).is_err());
    assert!(pmt.get_node(NODE23).is_err());
    assert!(pmt.get_node(NODE30).is_err());
    assert!(pmt.get_node(NODE31).is_err());
}

/// Checks that the request of the path from the leaf which is not in the PMT will cause an error.
#[test]
fn err_get_path() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    assert!(pmt.get_path(NODE22).is_err());
    assert!(pmt.get_path(NODE23).is_err());
    assert!(pmt.get_path(NODE30).is_err());
    assert!(pmt.get_path(NODE31).is_err());
}

#[test]
fn err_update_leaf() {
    let mt = MerkleTree::new(VALUES8.to_vec()).unwrap();
    let expected_root = mt.root();

    let ms = MerkleStore::from(&mt);

    let path33 = ms.get_path(expected_root, NODE33).unwrap();

    let mut pmt = PartialMerkleTree::with_paths([(3, path33.value.into(), path33.path)]).unwrap();

    assert!(pmt.update_leaf(NODE22, int_to_node(22).into()).is_err());
    assert!(pmt.update_leaf(NODE23, int_to_node(23).into()).is_err());
    assert!(pmt.update_leaf(NODE30, int_to_node(30).into()).is_err());
    assert!(pmt.update_leaf(NODE31, int_to_node(31).into()).is_err());
}
