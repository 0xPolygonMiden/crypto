use alloc::vec::Vec;

use super::{
    super::{InnerNodeInfo, Rpo256, RpoDigest},
    bit::TrueBitPositionIterator,
    Mmr, MmrPeaks, PartialMmr,
};
use crate::{
    merkle::{int_to_node, mmr::forest::{high_bitmask, Forest}, InOrderIndex, MerklePath, MerkleTree, MmrProof, NodeIndex},
    Felt, Word,
};

#[test]
fn test_position_equal_or_higher_than_leafs_is_never_contained() {
    let empty_forest = 0;
    for pos in 1..1024 {
        // pos is index, 0 based
        // tree is a length counter, 1 based
        // so a valid pos is always smaller, not equal, to tree
        assert_eq!(leaf_to_corresponding_tree(pos, pos), None);
        assert_eq!(leaf_to_corresponding_tree(pos, pos - 1), None);
        // and empty forest has no trees, so no position is valid
        assert_eq!(leaf_to_corresponding_tree(pos, empty_forest), None);
    }
}

#[test]
fn test_position_zero_is_always_contained_by_the_highest_tree() {
    for leaves in 1..1024usize {
        let tree = leaves.ilog2();
        assert_eq!(leaf_to_corresponding_tree(0, leaves), Some(tree));
    }
}

#[test]
fn test_leaf_to_corresponding_tree() {
    assert_eq!(leaf_to_corresponding_tree(0, 0b0001), Some(0));
    assert_eq!(leaf_to_corresponding_tree(0, 0b0010), Some(1));
    assert_eq!(leaf_to_corresponding_tree(0, 0b0011), Some(1));
    assert_eq!(leaf_to_corresponding_tree(0, 0b1011), Some(3));

    // position one is always owned by the left-most tree
    assert_eq!(leaf_to_corresponding_tree(1, 0b0010), Some(1));
    assert_eq!(leaf_to_corresponding_tree(1, 0b0011), Some(1));
    assert_eq!(leaf_to_corresponding_tree(1, 0b1011), Some(3));

    // position two starts as its own root, and then it is merged with the left-most tree
    assert_eq!(leaf_to_corresponding_tree(2, 0b0011), Some(0));
    assert_eq!(leaf_to_corresponding_tree(2, 0b0100), Some(2));
    assert_eq!(leaf_to_corresponding_tree(2, 0b1011), Some(3));

    // position tree is merged on the left-most tree
    assert_eq!(leaf_to_corresponding_tree(3, 0b0011), None);
    assert_eq!(leaf_to_corresponding_tree(3, 0b0100), Some(2));
    assert_eq!(leaf_to_corresponding_tree(3, 0b1011), Some(3));

    assert_eq!(leaf_to_corresponding_tree(4, 0b0101), Some(0));
    assert_eq!(leaf_to_corresponding_tree(4, 0b0110), Some(1));
    assert_eq!(leaf_to_corresponding_tree(4, 0b0111), Some(1));
    assert_eq!(leaf_to_corresponding_tree(4, 0b1000), Some(3));

    assert_eq!(leaf_to_corresponding_tree(12, 0b01101), Some(0));
    assert_eq!(leaf_to_corresponding_tree(12, 0b01110), Some(1));
    assert_eq!(leaf_to_corresponding_tree(12, 0b01111), Some(1));
    assert_eq!(leaf_to_corresponding_tree(12, 0b10000), Some(4));
}

#[test]
fn test_high_bitmask() {
    assert_eq!(high_bitmask(0), Forest(usize::MAX));
    assert_eq!(high_bitmask(1), Forest(usize::MAX << 1));
    assert_eq!(high_bitmask(usize::BITS - 2), Forest(0b11usize.rotate_right(2)));
    assert_eq!(high_bitmask(usize::BITS - 1), Forest(0b1usize.rotate_right(1)));
    assert_eq!(high_bitmask(usize::BITS), Forest(0), "overflow should be handled");
}

#[test]
fn test_nodes_in_forest() {
    assert_eq!(nodes_in_forest(0b0000), 0);
    assert_eq!(nodes_in_forest(0b0001), 1);
    assert_eq!(nodes_in_forest(0b0010), 3);
    assert_eq!(nodes_in_forest(0b0011), 4);
    assert_eq!(nodes_in_forest(0b0100), 7);
    assert_eq!(nodes_in_forest(0b0101), 8);
    assert_eq!(nodes_in_forest(0b0110), 10);
    assert_eq!(nodes_in_forest(0b0111), 11);
    assert_eq!(nodes_in_forest(0b1000), 15);
    assert_eq!(nodes_in_forest(0b1001), 16);
    assert_eq!(nodes_in_forest(0b1010), 18);
    assert_eq!(nodes_in_forest(0b1011), 19);
}

#[test]
fn test_nodes_in_forest_single_bit() {
    assert_eq!(nodes_in_forest(2usize.pow(0)), 2usize.pow(1) - 1);
    assert_eq!(nodes_in_forest(2usize.pow(1)), 2usize.pow(2) - 1);
    assert_eq!(nodes_in_forest(2usize.pow(2)), 2usize.pow(3) - 1);
    assert_eq!(nodes_in_forest(2usize.pow(3)), 2usize.pow(4) - 1);

    for bit in 0..(usize::BITS - 1) {
        let size = 2usize.pow(bit + 1) - 1;
        assert_eq!(nodes_in_forest(1usize << bit), size);
    }
}

const LEAVES: [RpoDigest; 7] = [
    int_to_node(0),
    int_to_node(1),
    int_to_node(2),
    int_to_node(3),
    int_to_node(4),
    int_to_node(5),
    int_to_node(6),
];

#[test]
fn test_mmr_simple() {
    let mut postorder = vec![
        LEAVES[0],
        LEAVES[1],
        merge(LEAVES[0], LEAVES[1]),
        LEAVES[2],
        LEAVES[3],
        merge(LEAVES[2], LEAVES[3]),
    ];
    postorder.push(merge(postorder[2], postorder[5]));
    postorder.push(LEAVES[4]);
    postorder.push(LEAVES[5]);
    postorder.push(merge(LEAVES[4], LEAVES[5]));
    postorder.push(LEAVES[6]);

    let mut mmr = Mmr::new();
    assert_eq!(mmr.forest().num_leaves(), 0);
    assert_eq!(mmr.nodes.len(), 0);

    mmr.add(LEAVES[0]);
    assert_eq!(mmr.forest().num_leaves(), 1);
    assert_eq!(mmr.nodes.len(), 1);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 1);
    assert_eq!(acc.peaks(), &[postorder[0]]);

    mmr.add(LEAVES[1]);
    assert_eq!(mmr.forest().num_leaves(), 2);
    assert_eq!(mmr.nodes.len(), 3);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 2);
    assert_eq!(acc.peaks(), &[postorder[2]]);

    mmr.add(LEAVES[2]);
    assert_eq!(mmr.forest().num_leaves(), 3);
    assert_eq!(mmr.nodes.len(), 4);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 3);
    assert_eq!(acc.peaks(), &[postorder[2], postorder[3]]);

    mmr.add(LEAVES[3]);
    assert_eq!(mmr.forest().num_leaves(), 4);
    assert_eq!(mmr.nodes.len(), 7);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 4);
    assert_eq!(acc.peaks(), &[postorder[6]]);

    mmr.add(LEAVES[4]);
    assert_eq!(mmr.forest().num_leaves(), 5);
    assert_eq!(mmr.nodes.len(), 8);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 5);
    assert_eq!(acc.peaks(), &[postorder[6], postorder[7]]);

    mmr.add(LEAVES[5]);
    assert_eq!(mmr.forest().num_leaves(), 6);
    assert_eq!(mmr.nodes.len(), 10);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 6);
    assert_eq!(acc.peaks(), &[postorder[6], postorder[9]]);

    mmr.add(LEAVES[6]);
    assert_eq!(mmr.forest().num_leaves(), 7);
    assert_eq!(mmr.nodes.len(), 11);
    assert_eq!(mmr.nodes.as_slice(), &postorder[0..mmr.nodes.len()]);

    let acc = mmr.peaks();
    assert_eq!(acc.num_leaves(), 7);
    assert_eq!(acc.peaks(), &[postorder[6], postorder[9], postorder[10]]);
}

#[test]
fn test_mmr_open() {
    let mmr: Mmr = LEAVES.into();
    let h01 = merge(LEAVES[0], LEAVES[1]);
    let h23 = merge(LEAVES[2], LEAVES[3]);

    // node at pos 7 is the root
    assert!(mmr.open(7).is_err(), "Element 7 is not in the tree, result should be None");

    // node at pos 6 is the root
    let empty: MerklePath = MerklePath::new(vec![]);
    let opening = mmr
        .open(6)
        .expect("Element 6 is contained in the tree, expected an opening result.");
    assert_eq!(opening.merkle_path, empty);
    assert_eq!(opening.forest, mmr.forest);
    assert_eq!(opening.position, 6);
    mmr.peaks().verify(LEAVES[6], opening).unwrap();

    // nodes 4,5 are depth 1
    let root_to_path = MerklePath::new(vec![LEAVES[4]]);
    let opening = mmr
        .open(5)
        .expect("Element 5 is contained in the tree, expected an opening result.");
    assert_eq!(opening.merkle_path, root_to_path);
    assert_eq!(opening.forest, mmr.forest);
    assert_eq!(opening.position, 5);
    mmr.peaks().verify(LEAVES[5], opening).unwrap();

    let root_to_path = MerklePath::new(vec![LEAVES[5]]);
    let opening = mmr
        .open(4)
        .expect("Element 4 is contained in the tree, expected an opening result.");
    assert_eq!(opening.merkle_path, root_to_path);
    assert_eq!(opening.forest, mmr.forest);
    assert_eq!(opening.position, 4);
    mmr.peaks().verify(LEAVES[4], opening).unwrap();

    // nodes 0,1,2,3 are detph 2
    let root_to_path = MerklePath::new(vec![LEAVES[2], h01]);
    let opening = mmr
        .open(3)
        .expect("Element 3 is contained in the tree, expected an opening result.");
    assert_eq!(opening.merkle_path, root_to_path);
    assert_eq!(opening.forest, mmr.forest);
    assert_eq!(opening.position, 3);
    mmr.peaks().verify(LEAVES[3], opening).unwrap();

    let root_to_path = MerklePath::new(vec![LEAVES[3], h01]);
    let opening = mmr
        .open(2)
        .expect("Element 2 is contained in the tree, expected an opening result.");
    assert_eq!(opening.merkle_path, root_to_path);
    assert_eq!(opening.forest, mmr.forest);
    assert_eq!(opening.position, 2);
    mmr.peaks().verify(LEAVES[2], opening).unwrap();

    let root_to_path = MerklePath::new(vec![LEAVES[0], h23]);
    let opening = mmr
        .open(1)
        .expect("Element 1 is contained in the tree, expected an opening result.");
    assert_eq!(opening.merkle_path, root_to_path);
    assert_eq!(opening.forest, mmr.forest);
    assert_eq!(opening.position, 1);
    mmr.peaks().verify(LEAVES[1], opening).unwrap();

    let root_to_path = MerklePath::new(vec![LEAVES[1], h23]);
    let opening = mmr
        .open(0)
        .expect("Element 0 is contained in the tree, expected an opening result.");
    assert_eq!(opening.merkle_path, root_to_path);
    assert_eq!(opening.forest, mmr.forest);
    assert_eq!(opening.position, 0);
    mmr.peaks().verify(LEAVES[0], opening).unwrap();
}

#[test]
fn test_mmr_open_older_version() {
    let mmr: Mmr = LEAVES.into();

    fn is_even(v: &usize) -> bool {
        v & 1 == 0
    }

    // merkle path of a node is empty if there are no elements to pair with it
    for pos in (0..mmr.forest().num_leaves()).filter(is_even) {
        let forest = Forest(pos + 1);
        let proof = mmr.open_at(pos, forest).unwrap();
        assert_eq!(proof.forest, forest);
        assert_eq!(proof.merkle_path.nodes(), []);
        assert_eq!(proof.position, pos);
    }

    // openings match that of a merkle tree
    let mtree: MerkleTree = LEAVES[..4].try_into().unwrap();
    for forest in 4..=LEAVES.len() {
        let forest = Forest(forest);
        for pos in 0..4 {
            let idx = NodeIndex::new(2, pos).unwrap();
            let path = mtree.get_path(idx).unwrap();
            let proof = mmr.open_at(pos as usize, forest).unwrap();
            assert_eq!(path, proof.merkle_path);
        }
    }
    let mtree: MerkleTree = LEAVES[4..6].try_into().unwrap();
    for forest in 6..=LEAVES.len() {
        let forest = Forest(forest);
        for pos in 0..2 {
            let idx = NodeIndex::new(1, pos).unwrap();
            let path = mtree.get_path(idx).unwrap();
            // account for the bigger tree with 4 elements
            let mmr_pos = (pos + 4) as usize;
            let proof = mmr.open_at(mmr_pos, forest).unwrap();
            assert_eq!(path, proof.merkle_path);
        }
    }
}

/// Tests the openings of a simple Mmr with a single tree of depth 8.
#[test]
fn test_mmr_open_eight() {
    let leaves = [
        int_to_node(0),
        int_to_node(1),
        int_to_node(2),
        int_to_node(3),
        int_to_node(4),
        int_to_node(5),
        int_to_node(6),
        int_to_node(7),
    ];

    let mtree: MerkleTree = leaves.as_slice().try_into().unwrap();
    let forest = Forest(leaves.len());
    let mmr: Mmr = leaves.into();
    let root = mtree.root();

    let position = 0;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(position as u64, leaves[position]).unwrap(), root);

    let position = 1;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(position as u64, leaves[position]).unwrap(), root);

    let position = 2;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(position as u64, leaves[position]).unwrap(), root);

    let position = 3;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(position as u64, leaves[position]).unwrap(), root);

    let position = 4;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(position as u64, leaves[position]).unwrap(), root);

    let position = 5;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(position as u64, leaves[position]).unwrap(), root);

    let position = 6;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(position as u64, leaves[position]).unwrap(), root);

    let position = 7;
    let proof = mmr.open(position).unwrap();
    let merkle_path = mtree.get_path(NodeIndex::new(3, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(position as u64, leaves[position]).unwrap(), root);
}

/// Tests the openings of Mmr with a 3 trees of depths 4, 2, and 1.
#[test]
fn test_mmr_open_seven() {
    let mtree1: MerkleTree = LEAVES[..4].try_into().unwrap();
    let mtree2: MerkleTree = LEAVES[4..6].try_into().unwrap();

    let forest = Forest(LEAVES.len());
    let mmr: Mmr = LEAVES.into();

    let position = 0;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath =
        mtree1.get_path(NodeIndex::new(2, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(0, LEAVES[0]).unwrap(), mtree1.root());

    let position = 1;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath =
        mtree1.get_path(NodeIndex::new(2, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(1, LEAVES[1]).unwrap(), mtree1.root());

    let position = 2;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath =
        mtree1.get_path(NodeIndex::new(2, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(2, LEAVES[2]).unwrap(), mtree1.root());

    let position = 3;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath =
        mtree1.get_path(NodeIndex::new(2, position as u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(3, LEAVES[3]).unwrap(), mtree1.root());

    let position = 4;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath = mtree2.get_path(NodeIndex::new(1, 0u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(0, LEAVES[4]).unwrap(), mtree2.root());

    let position = 5;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath = mtree2.get_path(NodeIndex::new(1, 1u64).unwrap()).unwrap();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(1, LEAVES[5]).unwrap(), mtree2.root());

    let position = 6;
    let proof = mmr.open(position).unwrap();
    let merkle_path: MerklePath = [].as_ref().into();
    assert_eq!(proof, MmrProof { forest, position, merkle_path });
    assert_eq!(proof.merkle_path.compute_root(0, LEAVES[6]).unwrap(), LEAVES[6]);
}

#[test]
fn test_mmr_get() {
    let mmr: Mmr = LEAVES.into();
    assert_eq!(mmr.get(0).unwrap(), LEAVES[0], "value at pos 0 must correspond");
    assert_eq!(mmr.get(1).unwrap(), LEAVES[1], "value at pos 1 must correspond");
    assert_eq!(mmr.get(2).unwrap(), LEAVES[2], "value at pos 2 must correspond");
    assert_eq!(mmr.get(3).unwrap(), LEAVES[3], "value at pos 3 must correspond");
    assert_eq!(mmr.get(4).unwrap(), LEAVES[4], "value at pos 4 must correspond");
    assert_eq!(mmr.get(5).unwrap(), LEAVES[5], "value at pos 5 must correspond");
    assert_eq!(mmr.get(6).unwrap(), LEAVES[6], "value at pos 6 must correspond");
    assert!(mmr.get(7).is_err());
}

#[test]
fn test_mmr_invariants() {
    let mut mmr = Mmr::new();
    for v in 1..=1028 {
        mmr.add(int_to_node(v));
        let accumulator = mmr.peaks();
        assert_eq!(v as usize, mmr.forest().num_leaves(), "MMR leaf count must increase by one on every add");
        assert_eq!(
            v as usize,
            accumulator.num_leaves(),
            "MMR and its accumulator must match leaves count"
        );
        assert_eq!(
            accumulator.num_leaves().count_ones() as usize,
            accumulator.peaks().len(),
            "bits on leaves must match the number of peaks"
        );

        let expected_nodes: usize = TrueBitPositionIterator::new(mmr.forest())
            .map(|tree| tree.num_nodes())
            .sum();

        assert_eq!(
            expected_nodes,
            mmr.nodes.len(),
            "the sum of every tree size must be equal to the number of nodes in the MMR (forest: {:b})",
            mmr.forest(),
        );
    }
}

#[test]
fn test_bit_position_iterator() {
    assert_eq!(TrueBitPositionIterator::new(Forest(0)).count(), 0);
    assert_eq!(TrueBitPositionIterator::new(Forest(0)).rev().count(), 0);

    assert_eq!(TrueBitPositionIterator::new(Forest(1)).collect::<Vec<Forest>>(), vec![Forest(1)]);
    assert_eq!(TrueBitPositionIterator::new(Forest(1)).rev().collect::<Vec<Forest>>(), vec![Forest(1)],);

    assert_eq!(TrueBitPositionIterator::new(Forest(2)).collect::<Vec<Forest>>(), vec![Forest(2)]);
    assert_eq!(TrueBitPositionIterator::new(Forest(2)).rev().collect::<Vec<Forest>>(), vec![Forest(2)],);

    assert_eq!(TrueBitPositionIterator::new(Forest(3)).collect::<Vec<Forest>>(), vec![Forest(1), Forest(2)],);
    assert_eq!(TrueBitPositionIterator::new(Forest(3)).rev().collect::<Vec<Forest>>(), vec![Forest(2), Forest(1)],);

    // TODO: convert
    // assert_eq!(
    //     TrueBitPositionIterator::new(0b11010101).collect::<Vec<Forest>>(),
    //     vec![0, 2, 4, 6, 7],
    // );
    // assert_eq!(
    //     TrueBitPositionIterator::new(0b11010101).rev().collect::<Vec<Forest>>(),
    //     vec![7, 6, 4, 2, 0],
    // );
}

#[test]
fn test_mmr_inner_nodes() {
    let mmr: Mmr = LEAVES.into();
    let nodes: Vec<InnerNodeInfo> = mmr.inner_nodes().collect();

    let h01 = Rpo256::merge(&[LEAVES[0], LEAVES[1]]);
    let h23 = Rpo256::merge(&[LEAVES[2], LEAVES[3]]);
    let h0123 = Rpo256::merge(&[h01, h23]);
    let h45 = Rpo256::merge(&[LEAVES[4], LEAVES[5]]);
    let postorder = vec![
        InnerNodeInfo {
            value: h01,
            left: LEAVES[0],
            right: LEAVES[1],
        },
        InnerNodeInfo {
            value: h23,
            left: LEAVES[2],
            right: LEAVES[3],
        },
        InnerNodeInfo { value: h0123, left: h01, right: h23 },
        InnerNodeInfo {
            value: h45,
            left: LEAVES[4],
            right: LEAVES[5],
        },
    ];

    assert_eq!(postorder, nodes);
}

#[test]
fn test_mmr_peaks() {
    let mmr: Mmr = LEAVES.into();

    let forest = Forest(0b0001);
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[0]]);

    let forest = Forest(0b0010);
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[2]]);

    let forest = Forest(0b0011);
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[2], mmr.nodes[3]]);

    let forest = Forest(0b0100);
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[6]]);

    let forest = Forest(0b0101);
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[6], mmr.nodes[7]]);

    let forest = Forest(0b0110);
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[6], mmr.nodes[9]]);

    let forest = Forest(0b0111);
    let acc = mmr.peaks_at(forest).unwrap();
    assert_eq!(acc.num_leaves(), forest.num_leaves());
    assert_eq!(acc.peaks(), &[mmr.nodes[6], mmr.nodes[9], mmr.nodes[10]]);
}

#[test]
fn test_mmr_hash_peaks() {
    let mmr: Mmr = LEAVES.into();
    let peaks = mmr.peaks();

    let first_peak = Rpo256::merge(&[
        Rpo256::merge(&[LEAVES[0], LEAVES[1]]),
        Rpo256::merge(&[LEAVES[2], LEAVES[3]]),
    ]);
    let second_peak = Rpo256::merge(&[LEAVES[4], LEAVES[5]]);
    let third_peak = LEAVES[6];

    // minimum length is 16
    let mut expected_peaks = [first_peak, second_peak, third_peak].to_vec();
    expected_peaks.resize(16, RpoDigest::default());
    assert_eq!(peaks.hash_peaks(), Rpo256::hash_elements(&digests_to_elements(&expected_peaks)));
}

#[test]
fn test_mmr_peaks_hash_less_than_16() {
    let mut peaks = Vec::new();

    for i in 0..16 {
        peaks.push(int_to_node(i));

        let forest = Forest(1 << peaks.len()).all_smaller_trees();
        let accumulator = MmrPeaks::new(forest, peaks.clone()).unwrap();

        // minimum length is 16
        let mut expected_peaks = peaks.clone();
        expected_peaks.resize(16, RpoDigest::default());
        assert_eq!(
            accumulator.hash_peaks(),
            Rpo256::hash_elements(&digests_to_elements(&expected_peaks))
        );
    }
}

#[test]
fn test_mmr_peaks_hash_odd() {
    let peaks: Vec<_> = (0..=17).map(int_to_node).collect();

    let forest = Forest(1 << peaks.len()).all_smaller_trees();
    let accumulator = MmrPeaks::new(forest, peaks.clone()).unwrap();

    // odd length bigger than 16 is padded to the next even number
    let mut expected_peaks = peaks;
    expected_peaks.resize(18, RpoDigest::default());
    assert_eq!(
        accumulator.hash_peaks(),
        Rpo256::hash_elements(&digests_to_elements(&expected_peaks))
    );
}

#[test]
fn test_mmr_delta() {
    let mmr: Mmr = LEAVES.into();
    let acc = mmr.peaks();

    // original_forest can't have more elements
    assert!(
        mmr.get_delta(Forest(LEAVES.len() + 1), mmr.forest()).is_err(),
        "Can not provide updates for a newer Mmr"
    );

    // if the number of elements is the same there is no change
    assert!(
        mmr.get_delta(Forest(LEAVES.len()), mmr.forest()).unwrap().data.is_empty(),
        "There are no updates for the same Mmr version"
    );

    // missing the last element added, which is itself a tree peak
    assert_eq!(mmr.get_delta(Forest(6), mmr.forest()).unwrap().data, vec![acc.peaks()[2]], "one peak");

    // missing the sibling to complete the tree of depth 2, and the last element
    assert_eq!(
        mmr.get_delta(Forest(5), mmr.forest()).unwrap().data,
        vec![LEAVES[5], acc.peaks()[2]],
        "one sibling, one peak"
    );

    // missing the whole last two trees, only send the peaks
    assert_eq!(
        mmr.get_delta(Forest(4), mmr.forest()).unwrap().data,
        vec![acc.peaks()[1], acc.peaks()[2]],
        "two peaks"
    );

    // missing the sibling to complete the first tree, and the two last trees
    assert_eq!(
        mmr.get_delta(Forest(3), mmr.forest()).unwrap().data,
        vec![LEAVES[3], acc.peaks()[1], acc.peaks()[2]],
        "one sibling, two peaks"
    );

    // missing half of the first tree, only send the computed element (not the leaves), and the new
    // peaks
    assert_eq!(
        mmr.get_delta(Forest(2), mmr.forest()).unwrap().data,
        vec![mmr.nodes[5], acc.peaks()[1], acc.peaks()[2]],
        "one sibling, two peaks"
    );

    assert_eq!(
        mmr.get_delta(Forest(1), mmr.forest()).unwrap().data,
        vec![LEAVES[1], mmr.nodes[5], acc.peaks()[1], acc.peaks()[2]],
        "one sibling, two peaks"
    );

    assert_eq!(&mmr.get_delta(Forest::empty(), mmr.forest()).unwrap().data, acc.peaks(), "all peaks");
}

#[test]
fn test_mmr_delta_old_forest() {
    let mmr: Mmr = LEAVES.into();

    // from_forest must be smaller-or-equal to to_forest
    for version in 1..=mmr.forest().num_leaves() {
        assert!(mmr.get_delta(Forest(version + 1), Forest(version)).is_err());
    }

    // when from_forest and to_forest are equal, there are no updates
    for version in 1..=mmr.forest().num_leaves() {
        let version = Forest(version);
        let delta = mmr.get_delta(version, version).unwrap();
        assert!(delta.data.is_empty());
        assert_eq!(delta.forest, version);
    }

    // test update which merges the odd peak to the right
    for count in 0..(mmr.forest().num_leaves() / 2) {
        // *2 because every iteration tests a pair
        // +1 because the Mmr is 1-indexed
        let from_forest = Forest((count * 2) + 1);
        let to_forest = Forest((count * 2) + 2);
        let delta = mmr.get_delta(from_forest, to_forest).unwrap();

        // *2 because every iteration tests a pair
        // +1 because sibling is the odd element
        let sibling = (count * 2) + 1;
        assert_eq!(delta.data, [LEAVES[sibling]]);
        assert_eq!(delta.forest, to_forest);
    }

    let version = Forest(4);
    let delta = mmr.get_delta(Forest(1), version).unwrap();
    assert_eq!(delta.data, [mmr.nodes[1], mmr.nodes[5]]);
    assert_eq!(delta.forest, version);

    let version = Forest(5);
    let delta = mmr.get_delta(Forest(1), version).unwrap();
    assert_eq!(delta.data, [mmr.nodes[1], mmr.nodes[5], mmr.nodes[7]]);
    assert_eq!(delta.forest, version);
}

#[test]
fn test_partial_mmr_simple() {
    let mmr: Mmr = LEAVES.into();
    let peaks = mmr.peaks();
    let mut partial: PartialMmr = peaks.clone().into();

    // check initial state of the partial mmr
    assert_eq!(partial.peaks(), peaks);
    assert_eq!(partial.num_leaves(), peaks.num_leaves());
    assert_eq!(partial.num_leaves(), LEAVES.len());
    assert_eq!(partial.peaks().num_peaks(), 3);
    assert_eq!(partial.nodes.len(), 0);

    // check state after adding tracking one element
    let proof1 = mmr.open(0).unwrap();
    let el1 = mmr.get(proof1.position).unwrap();
    partial.track(proof1.position, el1, &proof1.merkle_path).unwrap();

    // check the number of nodes increased by the number of nodes in the proof
    assert_eq!(partial.nodes.len(), proof1.merkle_path.len());
    // check the values match
    let idx = InOrderIndex::from_leaf_pos(proof1.position);
    assert_eq!(partial.nodes[&idx.sibling()], proof1.merkle_path[0]);
    let idx = idx.parent();
    assert_eq!(partial.nodes[&idx.sibling()], proof1.merkle_path[1]);

    let proof2 = mmr.open(1).unwrap();
    let el2 = mmr.get(proof2.position).unwrap();
    partial.track(proof2.position, el2, &proof2.merkle_path).unwrap();

    // check the number of nodes increased by a single element (the one that is not shared)
    assert_eq!(partial.nodes.len(), 3);
    // check the values match
    let idx = InOrderIndex::from_leaf_pos(proof2.position);
    assert_eq!(partial.nodes[&idx.sibling()], proof2.merkle_path[0]);
    let idx = idx.parent();
    assert_eq!(partial.nodes[&idx.sibling()], proof2.merkle_path[1]);
}

#[test]
fn test_partial_mmr_update_single() {
    let mut full = Mmr::new();
    let zero = int_to_node(0);
    full.add(zero);
    let mut partial: PartialMmr = full.peaks().into();

    let proof = full.open(0).unwrap();
    partial.track(proof.position, zero, &proof.merkle_path).unwrap();

    for i in 1..100 {
        let node = int_to_node(i);
        full.add(node);
        let delta = full.get_delta(partial.forest(), full.forest()).unwrap();
        partial.apply(delta).unwrap();

        assert_eq!(partial.forest(), full.forest());
        assert_eq!(partial.peaks(), full.peaks());

        let proof1 = full.open(i as usize).unwrap();
        partial.track(proof1.position, node, &proof1.merkle_path).unwrap();
        let proof2 = partial.open(proof1.position).unwrap().unwrap();
        assert_eq!(proof1.merkle_path, proof2.merkle_path);
    }
}

#[test]
fn test_mmr_add_invalid_odd_leaf() {
    let mmr: Mmr = LEAVES.into();
    let acc = mmr.peaks();
    let mut partial: PartialMmr = acc.clone().into();

    let empty = MerklePath::new(Vec::new());

    // None of the other leaves should work
    for node in LEAVES.iter().cloned().rev().skip(1) {
        let result = partial.track(LEAVES.len() - 1, node, &empty);
        assert!(result.is_err());
    }

    let result = partial.track(LEAVES.len() - 1, LEAVES[6], &empty);
    assert!(result.is_ok());
}

/// Tests that a proof whose peak count exceeds the peak count of the MMR returns an error.
///
/// Here we manipulate the proof to return a peak index of 1 while the MMR only has 1 peak (with
/// index 0).
#[test]
#[should_panic]
fn test_mmr_proof_num_peaks_exceeds_current_num_peaks() {
    let mmr: Mmr = LEAVES[0..4].iter().cloned().into();
    let mut proof = mmr.open(3).unwrap();
    proof.forest = Forest(5);
    proof.position = 4;
    mmr.peaks().verify(LEAVES[3], proof).unwrap();
}

/// Tests that a proof whose peak count exceeds the peak count of the MMR returns an error.
///
/// We create an MmrProof for a leaf whose peak index to verify against is 1.
/// Then we add another leaf which results in an Mmr with just one peak due to trees
/// being merged. If we try to use the old proof against the new Mmr, we should get an error.
#[test]
#[should_panic]
fn test_mmr_old_proof_num_peaks_exceeds_current_num_peaks() {
    let leaves_len = 3;
    let mut mmr = Mmr::from(LEAVES[0..leaves_len].iter().cloned());

    let leaf_idx = leaves_len - 1;
    let proof = mmr.open(leaf_idx).unwrap();
    assert!(mmr.peaks().verify(LEAVES[leaf_idx], proof.clone()).is_ok());

    mmr.add(LEAVES[leaves_len]);
    mmr.peaks().verify(LEAVES[leaf_idx], proof).unwrap();
}

mod property_tests {
    use proptest::prelude::*;

    use super::leaf_to_corresponding_tree;

    proptest! {
        #[test]
        fn test_last_position_is_always_contained_in_the_last_tree(leaves in any::<usize>().prop_filter("cant have an empty tree", |v| *v != 0)) {
            let last_pos = leaves - 1;
            let lowest_bit = leaves.trailing_zeros();

            assert_eq!(
                leaf_to_corresponding_tree(last_pos, leaves),
                Some(lowest_bit),
            );
        }
    }

    proptest! {
        #[test]
        fn test_contained_tree_is_always_power_of_two((leaves, pos) in any::<usize>().prop_flat_map(|v| (Just(v), 0..v))) {
            let tree_bit = leaf_to_corresponding_tree(pos, leaves).expect("pos is smaller than leaves, there should always be a corresponding tree");
            let mask = 1usize << tree_bit;

            assert!(tree_bit < usize::BITS, "the result must be a bit in usize");
            assert!(mask & leaves != 0, "the result should be a tree in leaves");
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn digests_to_elements(digests: &[RpoDigest]) -> Vec<Felt> {
    digests.iter().flat_map(Word::from).collect()
}

// short hand for the rpo hash, used to make test code more concise and easy to read
fn merge(l: RpoDigest, r: RpoDigest) -> RpoDigest {
    Rpo256::merge(&[l, r])
}

/// Given a 0-indexed leaf position and the current forest, return the tree number responsible for
/// the position.
fn leaf_to_corresponding_tree(pos: usize, forest: usize) -> Option<u32> {
    Forest(forest).leaf_to_corresponding_tree(pos)
}


/// Return the total number of nodes of a given forest
const fn nodes_in_forest(forest: usize) -> usize {
    Forest(forest).num_nodes()
}
