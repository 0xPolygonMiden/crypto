use super::{
    super::{int_to_node, MerkleTree, RpoDigest, SimpleSmt},
    NodeIndex, Rpo256, Vec, Word,
};
use proptest::prelude::*;
use rand_utils::prng_array;

const KEYS4: [u64; 4] = [0, 1, 2, 3];
const KEYS8: [u64; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

const VALUES4: [Word; 4] = [
    int_to_node(1),
    int_to_node(2),
    int_to_node(3),
    int_to_node(4),
];

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

const ZERO_VALUES8: [Word; 8] = [int_to_node(0); 8];

#[test]
fn build_empty_tree() {
    let smt = SimpleSmt::new(3).unwrap();
    let mt = MerkleTree::new(ZERO_VALUES8.to_vec()).unwrap();
    assert_eq!(mt.root(), smt.root());
}

#[test]
fn empty_digests_are_consistent() {
    let depth = 5;
    let root = SimpleSmt::new(depth).unwrap().root();
    let computed: [RpoDigest; 2] = (0..depth).fold([Default::default(); 2], |state, _| {
        let digest = Rpo256::merge(&state);
        [digest; 2]
    });

    assert_eq!(Word::from(computed[0]), root);
}

#[test]
fn build_sparse_tree() {
    let mut smt = SimpleSmt::new(3).unwrap();
    let mut values = ZERO_VALUES8.to_vec();

    // insert single value
    let key = 6;
    let new_node = int_to_node(7);
    values[key as usize] = new_node;
    smt.insert_leaf(key, new_node)
        .expect("Failed to insert leaf");
    let mt2 = MerkleTree::new(values.clone()).unwrap();
    assert_eq!(mt2.root(), smt.root());
    assert_eq!(
        mt2.get_path(NodeIndex::new(3, 6)).unwrap(),
        smt.get_path(NodeIndex::new(3, 6)).unwrap()
    );

    // insert second value at distinct leaf branch
    let key = 2;
    let new_node = int_to_node(3);
    values[key as usize] = new_node;
    smt.insert_leaf(key, new_node)
        .expect("Failed to insert leaf");
    let mt3 = MerkleTree::new(values).unwrap();
    assert_eq!(mt3.root(), smt.root());
    assert_eq!(
        mt3.get_path(NodeIndex::new(3, 2)).unwrap(),
        smt.get_path(NodeIndex::new(3, 2)).unwrap()
    );
}

#[test]
fn build_full_tree() {
    let tree = SimpleSmt::new(2)
        .unwrap()
        .with_leaves(KEYS4.into_iter().zip(VALUES4.into_iter()))
        .unwrap();

    let (root, node2, node3) = compute_internal_nodes();
    assert_eq!(root, tree.root());
    assert_eq!(node2, tree.get_node(&NodeIndex::new(1, 0)).unwrap());
    assert_eq!(node3, tree.get_node(&NodeIndex::new(1, 1)).unwrap());
}

#[test]
fn get_values() {
    let tree = SimpleSmt::new(2)
        .unwrap()
        .with_leaves(KEYS4.into_iter().zip(VALUES4.into_iter()))
        .unwrap();

    // check depth 2
    assert_eq!(VALUES4[0], tree.get_node(&NodeIndex::new(2, 0)).unwrap());
    assert_eq!(VALUES4[1], tree.get_node(&NodeIndex::new(2, 1)).unwrap());
    assert_eq!(VALUES4[2], tree.get_node(&NodeIndex::new(2, 2)).unwrap());
    assert_eq!(VALUES4[3], tree.get_node(&NodeIndex::new(2, 3)).unwrap());
}

#[test]
fn get_path() {
    let tree = SimpleSmt::new(2)
        .unwrap()
        .with_leaves(KEYS4.into_iter().zip(VALUES4.into_iter()))
        .unwrap();

    let (_, node2, node3) = compute_internal_nodes();

    // check depth 2
    assert_eq!(
        vec![VALUES4[1], node3],
        *tree.get_path(NodeIndex::new(2, 0)).unwrap()
    );
    assert_eq!(
        vec![VALUES4[0], node3],
        *tree.get_path(NodeIndex::new(2, 1)).unwrap()
    );
    assert_eq!(
        vec![VALUES4[3], node2],
        *tree.get_path(NodeIndex::new(2, 2)).unwrap()
    );
    assert_eq!(
        vec![VALUES4[2], node2],
        *tree.get_path(NodeIndex::new(2, 3)).unwrap()
    );

    // check depth 1
    assert_eq!(vec![node3], *tree.get_path(NodeIndex::new(1, 0)).unwrap());
    assert_eq!(vec![node2], *tree.get_path(NodeIndex::new(1, 1)).unwrap());
}

#[test]
fn update_leaf() {
    let mut tree = SimpleSmt::new(3)
        .unwrap()
        .with_leaves(KEYS8.into_iter().zip(VALUES8.into_iter()))
        .unwrap();

    // update one value
    let key = 3;
    let new_node = int_to_node(9);
    let mut expected_values = VALUES8.to_vec();
    expected_values[key] = new_node;
    let expected_tree = SimpleSmt::new(3)
        .unwrap()
        .with_leaves(KEYS8.into_iter().zip(expected_values.clone().into_iter()))
        .unwrap();

    tree.update_leaf(key as u64, new_node).unwrap();
    assert_eq!(expected_tree.root, tree.root);

    // update another value
    let key = 6;
    let new_node = int_to_node(10);
    expected_values[key] = new_node;
    let expected_tree = SimpleSmt::new(3)
        .unwrap()
        .with_leaves(KEYS8.into_iter().zip(expected_values.into_iter()))
        .unwrap();

    tree.update_leaf(key as u64, new_node).unwrap();
    assert_eq!(expected_tree.root, tree.root);
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

    let depth = 3;
    let entries = vec![(0, a), (1, b), (4, c), (7, d)];
    let tree = SimpleSmt::new(depth).unwrap().with_leaves(entries).unwrap();

    assert_eq!(tree.root(), Word::from(k));

    let cases: Vec<(u8, u64, Vec<Word>)> = vec![
        (3, 0, vec![b, f, j]),
        (3, 1, vec![a, f, j]),
        (3, 4, vec![z, h, i]),
        (3, 7, vec![z, g, i]),
        (2, 0, vec![f, j]),
        (2, 1, vec![e, j]),
        (2, 2, vec![h, i]),
        (2, 3, vec![g, i]),
        (1, 0, vec![j]),
        (1, 1, vec![i]),
    ];

    for (depth, key, path) in cases {
        let opening = tree.get_path(NodeIndex::new(depth, key)).unwrap();

        assert_eq!(path, *opening);
    }
}

proptest! {
    #[test]
    fn arbitrary_openings_single_leaf(
        depth in SimpleSmt::MIN_DEPTH..SimpleSmt::MAX_DEPTH,
        key in prop::num::u64::ANY,
        leaf in prop::num::u64::ANY,
    ) {
        let mut tree = SimpleSmt::new(depth).unwrap();

        let key = key % (1 << depth as u64);
        let leaf = int_to_node(leaf);

        tree.insert_leaf(key, leaf.into()).unwrap();
        tree.get_leaf_path(key).unwrap();

        // traverse to root, fetching all paths
        for d in 1..depth {
            let k = key >> (depth - d);
            tree.get_path(NodeIndex::new(d, k)).unwrap();
        }
    }

    #[test]
    fn arbitrary_openings_multiple_leaves(
        depth in SimpleSmt::MIN_DEPTH..SimpleSmt::MAX_DEPTH,
        count in 2u8..10u8,
        ref seed in any::<[u8; 32]>()
    ) {
        let mut tree = SimpleSmt::new(depth).unwrap();
        let mut seed = *seed;
        let leaves = (1 << depth) - 1;

        for _ in 0..count {
            seed = prng_array(seed);

            let mut key = [0u8; 8];
            let mut leaf = [0u8; 8];

            key.copy_from_slice(&seed[..8]);
            leaf.copy_from_slice(&seed[8..16]);

            let key = u64::from_le_bytes(key);
            let key = key % leaves;
            let leaf = u64::from_le_bytes(leaf);
            let leaf = int_to_node(leaf);

            tree.insert_leaf(key, leaf).unwrap();
            tree.get_leaf_path(key).unwrap();
        }
    }
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn compute_internal_nodes() -> (Word, Word, Word) {
    let node2 = Rpo256::hash_elements(&[VALUES4[0], VALUES4[1]].concat());
    let node3 = Rpo256::hash_elements(&[VALUES4[2], VALUES4[3]].concat());
    let root = Rpo256::merge(&[node2, node3]);

    (root.into(), node2.into(), node3.into())
}
