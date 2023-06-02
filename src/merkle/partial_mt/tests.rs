use crate::hash::rpo::RpoDigest;

use super::{
    super::{int_to_digest, int_to_node, NodeIndex},
    PartialMerkleTree, Rpo256,
};

// TEST DATA
// ================================================================================================

const NODE22: NodeIndex = NodeIndex::new_unchecked(2, 2);

const NODE32: NodeIndex = NodeIndex::new_unchecked(3, 2);
const NODE33: NodeIndex = NodeIndex::new_unchecked(3, 3);

// TESTS
// ================================================================================================

// with_paths CONSTRUCTOR TESTS
// ------------------------------------------------------------------------------------------------

#[test]
fn get_root() {
    let leaf0 = int_to_digest(0);
    let leaf1 = int_to_digest(1);
    let leaf2 = int_to_digest(2);
    let leaf3 = int_to_digest(3);

    let parent0 = calculate_parent_hash(leaf0, 0, leaf1);
    let parent1 = calculate_parent_hash(leaf2, 2, leaf3);

    let root_exp = calculate_parent_hash(parent0, 0, parent1);

    let set =
        super::PartialMerkleTree::with_paths([(0, leaf0, vec![*leaf1, *parent1].into())]).unwrap();

    assert_eq!(set.root(), root_exp);
}

#[test]
fn add_and_get_paths() {
    let value32 = int_to_digest(32);
    let value33 = int_to_digest(33);
    let value20 = int_to_digest(20);
    let value22 = int_to_digest(22);
    let value23 = int_to_digest(23);

    let value21 = Rpo256::merge(&[value32, value33]);
    let value10 = Rpo256::merge(&[value20, value21]);
    let value11 = Rpo256::merge(&[value22, value23]);

    let path_33 = vec![*value32, *value20, *value11];

    let path_22 = vec![*value23, *value10];

    let pmt = PartialMerkleTree::with_paths([
        (3, value33, path_33.clone().into()),
        (2, value22, path_22.clone().into()),
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
    let hash_6 = int_to_digest(6);
    let index = NodeIndex::make(3, 6);
    let pmt = PartialMerkleTree::with_paths([(index.value(), hash_6, path_6.into())]).unwrap();

    assert_eq!(int_to_digest(6u64), pmt.get_node(index).unwrap());
}

#[test]
fn update_leaf() {
    let value32 = int_to_digest(32);
    let value33 = int_to_digest(33);
    let value20 = int_to_digest(20);
    let value22 = int_to_digest(22);
    let value23 = int_to_digest(23);

    let value21 = Rpo256::merge(&[value32, value33]);
    let value10 = Rpo256::merge(&[value20, value21]);
    let value11 = Rpo256::merge(&[value22, value23]);

    let path_33 = vec![*value32, *value20, *value11];

    let path_22 = vec![*value23, *value10];

    let mut pmt =
        PartialMerkleTree::with_paths([(3, value33, path_33.into()), (2, value22, path_22.into())])
            .unwrap();

    let new_value32 = int_to_digest(132);
    let new_value21 = Rpo256::merge(&[new_value32, value33]);
    let new_value10 = Rpo256::merge(&[value20, new_value21]);
    let expected_root = Rpo256::merge(&[new_value10, value11]);

    let old_leaf = pmt.update_leaf(NODE32, new_value32).unwrap();

    assert_eq!(value32, old_leaf);

    let new_root = pmt.root();

    assert_eq!(new_root, expected_root);
}

#[test]
fn check_leaf_depth() {
    let value32 = int_to_digest(32);
    let value33 = int_to_digest(33);
    let value20 = int_to_digest(20);
    let value22 = int_to_digest(22);
    let value23 = int_to_digest(23);

    let value11 = Rpo256::merge(&[value22, value23]);

    let path_33 = vec![*value32, *value20, *value11];

    let pmt = PartialMerkleTree::with_paths([(3, value33, path_33.into())]).unwrap();

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
fn calculate_parent_hash(node: RpoDigest, node_pos: u64, sibling: RpoDigest) -> RpoDigest {
    let parity = node_pos & 1;
    if parity == 0 {
        Rpo256::merge(&[node, sibling])
    } else {
        Rpo256::merge(&[sibling, node])
    }
}
