use crate::hash::rpo::RpoDigest;

use super::{
    super::{int_to_node, NodeIndex},
    InnerNodeInfo, MerkleError, PartialMerkleTree, Rpo256, Vec, Word,
};

// TEST DATA
// ================================================================================================

const ROOT_NODE: NodeIndex = NodeIndex::new_unchecked(0, 0);

const NODE10: NodeIndex = NodeIndex::new_unchecked(1, 0);
const NODE11: NodeIndex = NodeIndex::new_unchecked(1, 1);

const NODE20: NodeIndex = NodeIndex::new_unchecked(2, 0);
const NODE21: NodeIndex = NodeIndex::new_unchecked(2, 1);
const NODE22: NodeIndex = NodeIndex::new_unchecked(2, 2);
const NODE23: NodeIndex = NodeIndex::new_unchecked(2, 3);

const NODE32: NodeIndex = NodeIndex::new_unchecked(3, 2);
const NODE33: NodeIndex = NodeIndex::new_unchecked(3, 3);

// TESTS
// ================================================================================================

// with_paths CONSTRUCTOR TESTS
// ------------------------------------------------------------------------------------------------

#[test]
fn get_root() {
    let leaf0 = int_to_node(0);
    let leaf1 = int_to_node(1);
    let leaf2 = int_to_node(2);
    let leaf3 = int_to_node(3);

    let parent0 = calculate_parent_hash(leaf0, 0, leaf1);
    let parent1 = calculate_parent_hash(leaf2, 2, leaf3);

    let root_exp = calculate_parent_hash(parent0, 0, parent1);

    let set = super::PartialMerkleTree::with_paths([(NODE20, leaf0, vec![leaf1, parent1].into())])
        .unwrap();

    assert_eq!(set.root(), root_exp);
}

#[test]
fn add_and_get_paths() {
    let value32 = int_to_node(32).into();
    let value33 = int_to_node(33).into();
    let value20 = int_to_node(20).into();
    let value22 = int_to_node(22).into();
    let value23 = int_to_node(23).into();

    let value21 = Rpo256::merge(&[value32, value33]);
    let value10 = Rpo256::merge(&[value20, value21]);
    let value11 = Rpo256::merge(&[value22, value23]);

    let path_33 = vec![*value32, *value20, *value11];

    let path_22 = vec![*value23, *value10];

    let pmt = PartialMerkleTree::with_paths([
        (NODE33, *value33, path_33.clone().into()),
        (NODE22, *value22, path_22.clone().into()),
    ])
    .unwrap();
    let stored_path_33 = pmt.get_path(NODE33).unwrap();
    let stored_path_22 = pmt.get_path(NODE22).unwrap();

    assert_eq!(path_33, *stored_path_33);
    assert_eq!(path_22, *stored_path_22);
}

#[test]
fn get_node() {
    let path_6 = vec![int_to_node(7), int_to_node(45), int_to_node(123)];
    let hash_6 = int_to_node(6);
    let index = NodeIndex::make(3, 6);
    let pmt = PartialMerkleTree::with_paths([(index, hash_6, path_6.into())]).unwrap();

    assert_eq!(int_to_node(6u64), *pmt.get_node(index).unwrap());
}

#[test]
fn update_leaf() {
    let value32 = int_to_node(32).into();
    let value33 = int_to_node(33).into();
    let value20 = int_to_node(20).into();
    let value22 = int_to_node(22).into();
    let value23 = int_to_node(23).into();

    let value21 = Rpo256::merge(&[value32, value33]);
    let value10 = Rpo256::merge(&[value20, value21]);
    let value11 = Rpo256::merge(&[value22, value23]);

    let path_33 = vec![*value32, *value20, *value11];

    let path_22 = vec![*value23, *value10];

    let mut pmt = PartialMerkleTree::with_paths([
        (NODE33, *value33, path_33.into()),
        (NODE22, *value22, path_22.into()),
    ])
    .unwrap();

    let new_value32 = int_to_node(132).into();
    let new_value21 = Rpo256::merge(&[new_value32, value33]);
    let new_value10 = Rpo256::merge(&[value20, new_value21]);
    let expected_root = Rpo256::merge(&[new_value10, value11]);

    let old_leaf = pmt.update_leaf(NODE32, new_value32).unwrap();

    assert_eq!(value32, old_leaf);

    let new_root = pmt.root();

    assert_eq!(new_root, *expected_root);
}

#[test]
fn test_inner_node_iterator() -> Result<(), MerkleError> {
    let value32 = int_to_node(32).into();
    let value33 = int_to_node(33).into();
    let value20 = int_to_node(20).into();
    let value22 = int_to_node(22).into();
    let value23 = int_to_node(23).into();

    let value21 = Rpo256::merge(&[value32, value33]);
    let value10 = Rpo256::merge(&[value20, value21]);
    let value11 = Rpo256::merge(&[value22, value23]);
    let root = Rpo256::merge(&[value10, value11]);

    let path_33 = vec![*value32, *value20, *value11];

    let path_22 = vec![*value23, *value10];

    let pmt = PartialMerkleTree::with_paths([
        (NODE33, *value33, path_33.into()),
        (NODE22, *value22, path_22.into()),
    ])
    .unwrap();

    assert_eq!(root, pmt.get_node(ROOT_NODE).unwrap());
    assert_eq!(value10, pmt.get_node(NODE10).unwrap());
    assert_eq!(value11, pmt.get_node(NODE11).unwrap());
    assert_eq!(value20, pmt.get_node(NODE20).unwrap());
    assert_eq!(value21, pmt.get_node(NODE21).unwrap());
    assert_eq!(value22, pmt.get_node(NODE22).unwrap());
    assert_eq!(value23, pmt.get_node(NODE23).unwrap());
    assert_eq!(value32, pmt.get_node(NODE32).unwrap());
    assert_eq!(value33, pmt.get_node(NODE33).unwrap());

    let nodes: Vec<InnerNodeInfo> = pmt.inner_nodes().collect();
    let expected = vec![
        InnerNodeInfo {
            value: *root,
            left: *value10,
            right: *value11,
        },
        InnerNodeInfo {
            value: *value10,
            left: *value20,
            right: *value21,
        },
        InnerNodeInfo {
            value: *value11,
            left: *value22,
            right: *value23,
        },
        InnerNodeInfo {
            value: *value21,
            left: *value32,
            right: *value33,
        },
    ];
    assert_eq!(nodes, expected);

    Ok(())
}

#[test]
fn check_leaf_depth() {
    let value32: RpoDigest = int_to_node(32).into();
    let value33: RpoDigest = int_to_node(33).into();
    let value20: RpoDigest = int_to_node(20).into();
    let value22 = int_to_node(22).into();
    let value23 = int_to_node(23).into();

    let value11 = Rpo256::merge(&[value22, value23]);

    let path_33 = vec![*value32, *value20, *value11];

    let pmt = PartialMerkleTree::with_paths([(NODE33, *value33, path_33.into())]).unwrap();

    assert_eq!(pmt.get_leaf_depth(0).unwrap(), 2);
    assert_eq!(pmt.get_leaf_depth(1).unwrap(), 2);
    assert_eq!(pmt.get_leaf_depth(2).unwrap(), 3);
    assert_eq!(pmt.get_leaf_depth(3).unwrap(), 3);
    assert_eq!(pmt.get_leaf_depth(4).unwrap(), 1);
    assert_eq!(pmt.get_leaf_depth(5).unwrap(), 1);
    assert_eq!(pmt.get_leaf_depth(6).unwrap(), 1);
    assert_eq!(pmt.get_leaf_depth(7).unwrap(), 1);
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

/// Calculates the hash of the parent node by two sibling ones
/// - node — current node
/// - node_pos — position of the current node
/// - sibling — neighboring vertex in the tree
fn calculate_parent_hash(node: Word, node_pos: u64, sibling: Word) -> Word {
    let parity = node_pos & 1;
    if parity == 0 {
        Rpo256::merge(&[node.into(), sibling.into()]).into()
    } else {
        Rpo256::merge(&[sibling.into(), node.into()]).into()
    }
}
