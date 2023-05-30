use super::{
    super::{int_to_node, MerkleTree, NodeIndex, RpoDigest},
    BTreeMap, InnerNodeInfo, MerkleError, PartialMerkleTree, Rpo256, Vec, Word, EMPTY_WORD,
};

// TEST DATA
// ================================================================================================

const NODE10: NodeIndex = NodeIndex::new_unchecked(1, 0);
const NODE11: NodeIndex = NodeIndex::new_unchecked(1, 1);

const NODE20: NodeIndex = NodeIndex::new_unchecked(2, 0);
const NODE21: NodeIndex = NodeIndex::new_unchecked(2, 1);
const NODE22: NodeIndex = NodeIndex::new_unchecked(2, 2);
const NODE23: NodeIndex = NodeIndex::new_unchecked(2, 3);

const NODE30: NodeIndex = NodeIndex::new_unchecked(3, 0);
const NODE31: NodeIndex = NodeIndex::new_unchecked(3, 1);
const NODE32: NodeIndex = NodeIndex::new_unchecked(3, 2);
const NODE34: NodeIndex = NodeIndex::new_unchecked(3, 4);
const NODE35: NodeIndex = NodeIndex::new_unchecked(3, 5);
const NODE36: NodeIndex = NodeIndex::new_unchecked(3, 6);
const NODE37: NodeIndex = NodeIndex::new_unchecked(3, 7);

const KEYS4: [NodeIndex; 4] = [NODE20, NODE21, NODE22, NODE23];

const WVALUES4: [Word; 4] = [int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];
const DVALUES4: [RpoDigest; 4] = [
    RpoDigest::new(int_to_node(1)),
    RpoDigest::new(int_to_node(2)),
    RpoDigest::new(int_to_node(3)),
    RpoDigest::new(int_to_node(4)),
];

const ZERO_VALUES8: [Word; 8] = [int_to_node(0); 8];

// TESTS
// ================================================================================================

#[test]
fn build_partial_tree() {
    // insert single value
    let mut pmt = PartialMerkleTree::new();

    let mut values = ZERO_VALUES8.to_vec();
    let key = NODE36;
    let new_node = int_to_node(7);
    values[key.value() as usize] = new_node;

    let hash0 = Rpo256::merge(&[int_to_node(0).into(), int_to_node(0).into()]);
    let hash00 = Rpo256::merge(&[hash0, hash0]);

    pmt.update_leaf(NODE10, hash00).expect("Failed to update leaf");
    pmt.update_leaf(NODE22, hash0).expect("Failed to update leaf");
    let old_value = pmt.update_leaf(key, new_node.into()).expect("Failed to update leaf");

    let mt2 = MerkleTree::new(values.clone()).unwrap();
    assert_eq!(mt2.root(), pmt.root());
    assert_eq!(mt2.get_path(NODE36).unwrap(), pmt.get_path(NODE36).unwrap());
    assert_eq!(*old_value, EMPTY_WORD);

    // insert second value at distinct leaf branch
    let key = NODE32;
    let new_node = int_to_node(3);
    values[key.value() as usize] = new_node;
    pmt.update_leaf(NODE20, hash0).expect("Failed to update leaf");
    let old_value = pmt.update_leaf(key, new_node.into()).expect("Failed to update leaf");
    let mt3 = MerkleTree::new(values).unwrap();
    assert_eq!(mt3.root(), pmt.root());
    assert_eq!(mt3.get_path(NODE32).unwrap(), pmt.get_path(NODE32).unwrap());
    assert_eq!(*old_value, EMPTY_WORD);
}

#[test]
fn test_depth2_tree() {
    let tree = PartialMerkleTree::with_leaves(KEYS4.into_iter().zip(DVALUES4.into_iter())).unwrap();

    // check internal structure
    let (root, node2, node3) = compute_internal_nodes();
    assert_eq!(root, tree.root());
    assert_eq!(node2, tree.get_node(NODE10).unwrap());
    assert_eq!(node3, tree.get_node(NODE11).unwrap());

    // check get_node()
    assert_eq!(WVALUES4[0], tree.get_node(NODE20).unwrap());
    assert_eq!(WVALUES4[1], tree.get_node(NODE21).unwrap());
    assert_eq!(WVALUES4[2], tree.get_node(NODE22).unwrap());
    assert_eq!(WVALUES4[3], tree.get_node(NODE23).unwrap());

    // check get_path(): depth 2
    assert_eq!(vec![WVALUES4[1], node3], *tree.get_path(NODE20).unwrap());
    assert_eq!(vec![WVALUES4[0], node3], *tree.get_path(NODE21).unwrap());
    assert_eq!(vec![WVALUES4[3], node2], *tree.get_path(NODE22).unwrap());
    assert_eq!(vec![WVALUES4[2], node2], *tree.get_path(NODE23).unwrap());

    // check get_path(): depth 1
    assert_eq!(vec![node3], *tree.get_path(NODE10).unwrap());
    assert_eq!(vec![node2], *tree.get_path(NODE11).unwrap());
}

#[test]
fn test_inner_node_iterator() -> Result<(), MerkleError> {
    let tree = PartialMerkleTree::with_leaves(KEYS4.into_iter().zip(DVALUES4.into_iter())).unwrap();

    // check depth 2
    assert_eq!(WVALUES4[0], tree.get_node(NODE20).unwrap());
    assert_eq!(WVALUES4[1], tree.get_node(NODE21).unwrap());
    assert_eq!(WVALUES4[2], tree.get_node(NODE22).unwrap());
    assert_eq!(WVALUES4[3], tree.get_node(NODE23).unwrap());

    // get parent nodes
    let root = tree.root();
    let l1n0 = tree.get_node(NODE10)?;
    let l1n1 = tree.get_node(NODE11)?;
    let l2n0 = tree.get_node(NODE20)?;
    let l2n1 = tree.get_node(NODE21)?;
    let l2n2 = tree.get_node(NODE22)?;
    let l2n3 = tree.get_node(NODE23)?;

    let nodes: Vec<InnerNodeInfo> = tree.inner_nodes().collect();
    let expected = vec![
        InnerNodeInfo {
            value: root,
            left: l1n0,
            right: l1n1,
        },
        InnerNodeInfo {
            value: l1n0,
            left: l2n0,
            right: l2n1,
        },
        InnerNodeInfo {
            value: l1n1,
            left: l2n2,
            right: l2n3,
        },
    ];
    assert_eq!(nodes, expected);

    Ok(())
}

#[test]
fn small_tree_opening_is_consistent() {
    //        ____k____
    //       /         \
    //     _i_         _j_
    //    /   \       /   \
    //   e     f     g     h
    //  / \   / \   / \   / \
    // a   b 0   0 c   0 0   d

    let z = Word::from(RpoDigest::default());

    let a = Word::from(Rpo256::merge(&[z.into(); 2]));
    let b = Word::from(Rpo256::merge(&[a.into(); 2]));
    let c = Word::from(Rpo256::merge(&[b.into(); 2]));
    let d = Word::from(Rpo256::merge(&[c.into(); 2]));

    let e = Word::from(Rpo256::merge(&[a.into(), b.into()]));
    let f = Word::from(Rpo256::merge(&[z.into(), z.into()]));
    let g = Word::from(Rpo256::merge(&[c.into(), z.into()]));
    let h = Word::from(Rpo256::merge(&[z.into(), d.into()]));

    let i = Word::from(Rpo256::merge(&[e.into(), f.into()]));
    let j = Word::from(Rpo256::merge(&[g.into(), h.into()]));

    let k = Word::from(Rpo256::merge(&[i.into(), j.into()]));

    // let depth = 3;
    // let entries = vec![(0, a), (1, b), (4, c), (7, d)];
    // let tree = SimpleSmt::with_leaves(depth, entries).unwrap();
    let entries = BTreeMap::from([
        (NODE30, a.into()),
        (NODE31, b.into()),
        (NODE34, c.into()),
        (NODE37, d.into()),
        (NODE21, f.into()),
    ]);

    let tree = PartialMerkleTree::with_leaves(entries).unwrap();

    assert_eq!(tree.root(), k);

    let cases: Vec<(NodeIndex, Vec<Word>)> = vec![
        (NODE30, vec![b, f, j]),
        (NODE31, vec![a, f, j]),
        (NODE34, vec![z, h, i]),
        (NODE37, vec![z, g, i]),
        (NODE20, vec![f, j]),
        (NODE21, vec![e, j]),
        (NODE22, vec![h, i]),
        (NODE23, vec![g, i]),
        (NODE10, vec![j]),
        (NODE11, vec![i]),
    ];

    for (index, path) in cases {
        let opening = tree.get_path(index).unwrap();

        assert_eq!(path, *opening);
    }
}

#[test]
fn fail_on_duplicates() {
    let entries = [
        (NODE31, int_to_node(1).into()),
        (NODE35, int_to_node(2).into()),
        (NODE31, int_to_node(3).into()),
    ];
    let smt = PartialMerkleTree::with_leaves(entries);
    assert!(smt.is_err());
}

#[test]
fn with_no_duplicates_empty_node() {
    let entries = [(NODE31, int_to_node(0).into()), (NODE35, int_to_node(2).into())];
    let smt = PartialMerkleTree::with_leaves(entries);
    assert!(smt.is_ok());
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn compute_internal_nodes() -> (Word, Word, Word) {
    let node2 = Rpo256::hash_elements(&[WVALUES4[0], WVALUES4[1]].concat());
    let node3 = Rpo256::hash_elements(&[WVALUES4[2], WVALUES4[3]].concat());
    let root = Rpo256::merge(&[node2, node3]);

    (root.into(), node2.into(), node3.into())
}
