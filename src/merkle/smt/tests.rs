use alloc::{collections::BTreeMap, vec::Vec};

use super::{
    InnerNode, LeafIndex, NodeIndex, PairComputations, SmtLeaf, SparseMerkleTree, SubtreeLeaf,
    SubtreeLeavesIter, COLS_PER_SUBTREE, SUBTREE_DEPTH,
};
use crate::{
    hash::rpo::RpoDigest,
    merkle::{Smt, SMT_DEPTH},
    Felt, Word, ONE,
};

fn smtleaf_to_subtree_leaf(leaf: &SmtLeaf) -> SubtreeLeaf {
    SubtreeLeaf {
        col: leaf.index().index.value(),
        hash: leaf.hash(),
    }
}

#[test]
fn test_sorted_pairs_to_leaves() {
    let entries: Vec<(RpoDigest, Word)> = vec![
        // Subtree 0.
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(16)]), [ONE; 4]),
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(17)]), [ONE; 4]),
        // Leaf index collision.
        (RpoDigest::new([ONE, ONE, Felt::new(10), Felt::new(20)]), [ONE; 4]),
        (RpoDigest::new([ONE, ONE, Felt::new(20), Felt::new(20)]), [ONE; 4]),
        // Subtree 1. Normal single leaf again.
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(400)]), [ONE; 4]), // Subtree boundary.
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(401)]), [ONE; 4]),
        // Subtree 2. Another normal leaf.
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(1024)]), [ONE; 4]),
    ];

    let control = Smt::with_entries(entries.clone()).unwrap();

    let control_leaves: Vec<SmtLeaf> = {
        let mut entries_iter = entries.iter().cloned();
        let mut next_entry = || entries_iter.next().unwrap();
        let control_leaves = vec![
            // Subtree 0.
            SmtLeaf::Single(next_entry()),
            SmtLeaf::Single(next_entry()),
            SmtLeaf::new_multiple(vec![next_entry(), next_entry()]).unwrap(),
            // Subtree 1.
            SmtLeaf::Single(next_entry()),
            SmtLeaf::Single(next_entry()),
            // Subtree 2.
            SmtLeaf::Single(next_entry()),
        ];
        assert_eq!(entries_iter.next(), None);
        control_leaves
    };

    let control_subtree_leaves: Vec<Vec<SubtreeLeaf>> = {
        let mut control_leaves_iter = control_leaves.iter();
        let mut next_leaf = || control_leaves_iter.next().unwrap();

        let control_subtree_leaves: Vec<Vec<SubtreeLeaf>> = [
            // Subtree 0.
            vec![next_leaf(), next_leaf(), next_leaf()],
            // Subtree 1.
            vec![next_leaf(), next_leaf()],
            // Subtree 2.
            vec![next_leaf()],
        ]
        .map(|subtree| subtree.into_iter().map(smtleaf_to_subtree_leaf).collect())
        .to_vec();
        assert_eq!(control_leaves_iter.next(), None);
        control_subtree_leaves
    };

    let subtrees: PairComputations<u64, SmtLeaf> = Smt::sorted_pairs_to_leaves(entries);
    // This will check that the hashes, columns, and subtree assignments all match.
    assert_eq!(subtrees.leaves, control_subtree_leaves);

    // Flattening and re-separating out the leaves into subtrees should have the same result.
    let mut all_leaves: Vec<SubtreeLeaf> = subtrees.leaves.clone().into_iter().flatten().collect();
    let re_grouped: Vec<Vec<_>> = SubtreeLeavesIter::from_leaves(&mut all_leaves).collect();
    assert_eq!(subtrees.leaves, re_grouped);

    // Then finally we might as well check the computed leaf nodes too.
    let control_leaves: BTreeMap<u64, SmtLeaf> = control
        .leaves()
        .map(|(index, value)| (index.index.value(), value.clone()))
        .collect();

    for (column, test_leaf) in subtrees.nodes {
        if test_leaf.is_empty() {
            continue;
        }
        let control_leaf = control_leaves
            .get(&column)
            .unwrap_or_else(|| panic!("no leaf node found for column {column}"));
        assert_eq!(control_leaf, &test_leaf);
    }
}

// Helper for the below tests.
fn generate_entries(pair_count: u64) -> Vec<(RpoDigest, Word)> {
    (0..pair_count)
        .map(|i| {
            let leaf_index = ((i as f64 / pair_count as f64) * (pair_count as f64)) as u64;
            let key = RpoDigest::new([ONE, ONE, Felt::new(i), Felt::new(leaf_index)]);
            let value = [ONE, ONE, ONE, Felt::new(i)];
            (key, value)
        })
        .collect()
}

#[test]
fn test_single_subtree() {
    // A single subtree's worth of leaves.
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries(entries.clone()).unwrap();

    // `entries` should already be sorted by nature of how we constructed it.
    let leaves = Smt::sorted_pairs_to_leaves(entries).leaves;
    let leaves = leaves.into_iter().next().unwrap();

    let (first_subtree, next_leaves) = Smt::build_subtree(leaves, SMT_DEPTH);
    assert!(!first_subtree.is_empty());

    // The inner nodes computed from that subtree should match the nodes in our control tree.
    for (index, node) in first_subtree.into_iter() {
        let control = control.get_inner_node(index);
        assert_eq!(
            control, node,
            "subtree-computed node at index {index:?} does not match control",
        );
    }

    // The "next leaves" returned should also have matching hashes from the equivalent nodes in
    // our control tree.
    for SubtreeLeaf { col, hash } in next_leaves {
        let index = NodeIndex::new(SMT_DEPTH - SUBTREE_DEPTH, col).unwrap();
        let control_node = control.get_inner_node(index);
        let control = control_node.hash();
        assert_eq!(
            control, hash,
            "subtree-computed next leaf at index {index:?} does not match control",
        );
    }
}

// Test that not just can we compute a subtree correctly, but we can feed the results of one
// subtree into computing another. In other words, test that `build_subtree()` is correctly
// composable.
#[test]
fn test_two_subtrees() {
    // Two subtrees' worth of leaves.
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 2;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries(entries.clone()).unwrap();

    let PairComputations { leaves, .. } = Smt::sorted_pairs_to_leaves(entries);
    // With two subtrees' worth of leaves, we should have exactly two subtrees.
    let [first, second]: [Vec<_>; 2] = leaves.try_into().unwrap();
    assert_eq!(first.len() as u64, PAIR_COUNT / 2);
    assert_eq!(first.len(), second.len());

    let mut current_depth = SMT_DEPTH;
    let mut next_leaves: Vec<SubtreeLeaf> = Default::default();

    let (first_nodes, leaves) = Smt::build_subtree(first, current_depth);
    next_leaves.extend(leaves);

    let (second_nodes, leaves) = Smt::build_subtree(second, current_depth);
    next_leaves.extend(leaves);

    // All new inner nodes + the new subtree-leaves should be 512, for one depth-cycle.
    let total_computed = first_nodes.len() + second_nodes.len() + next_leaves.len();
    assert_eq!(total_computed as u64, PAIR_COUNT);

    // Verify the computed nodes of both subtrees.
    let computed_nodes = first_nodes.clone().into_iter().chain(second_nodes);
    for (index, test_node) in computed_nodes {
        let control_node = control.get_inner_node(index);
        assert_eq!(
            control_node, test_node,
            "subtree-computed node at index {index:?} does not match control",
        );
    }

    current_depth -= SUBTREE_DEPTH;

    let (nodes, next_leaves) = Smt::build_subtree(next_leaves, current_depth);
    assert_eq!(nodes.len(), SUBTREE_DEPTH as usize);
    assert_eq!(next_leaves.len(), 1);

    for (index, test_node) in nodes {
        let control_node = control.get_inner_node(index);
        assert_eq!(
            control_node, test_node,
            "subtree-computed node at index {index:?} does not match control",
        );
    }

    for SubtreeLeaf { col, hash } in next_leaves {
        let index = NodeIndex::new(current_depth - SUBTREE_DEPTH, col).unwrap();
        let control_node = control.get_inner_node(index);
        let control = control_node.hash();
        assert_eq!(control, hash);
    }
}

#[test]
fn test_singlethreaded_subtrees() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries(entries.clone()).unwrap();

    let mut accumulated_nodes: BTreeMap<NodeIndex, InnerNode> = Default::default();

    let PairComputations {
        leaves: mut leaf_subtrees,
        nodes: test_leaves,
    } = Smt::sorted_pairs_to_leaves(entries);

    for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
        // There's no flat_map_unzip(), so this is the best we can do.
        let (nodes, subtrees): (Vec<BTreeMap<_, _>>, Vec<Vec<SubtreeLeaf>>) = leaf_subtrees
            .into_iter()
            .enumerate()
            .map(|(i, subtree)| {
                // Pre-assertions.
                assert!(
                    subtree.is_sorted(),
                    "subtree {i} at bottom-depth {current_depth} is not sorted",
                );
                assert!(
                    !subtree.is_empty(),
                    "subtree {i} at bottom-depth {current_depth} is empty!",
                );

                // Do actual things.
                let (nodes, next_leaves) = Smt::build_subtree(subtree, current_depth);
                // Post-assertions.
                assert!(next_leaves.is_sorted());

                for (&index, test_node) in nodes.iter() {
                    let control_node = control.get_inner_node(index);
                    assert_eq!(
                        test_node, &control_node,
                        "depth {} subtree {}: test node does not match control at index {:?}",
                        current_depth, i, index,
                    );
                }

                (nodes, next_leaves)
            })
            .unzip();

        // Update state between each depth iteration.

        let mut all_leaves: Vec<SubtreeLeaf> = subtrees.into_iter().flatten().collect();
        leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut all_leaves).collect();
        accumulated_nodes.extend(nodes.into_iter().flatten());

        assert!(!leaf_subtrees.is_empty(), "on depth {current_depth}");
    }

    // Make sure the true leaves match, first checking length and then checking each individual
    // leaf.
    let control_leaves: BTreeMap<_, _> = control.leaves().collect();
    let control_leaves_len = control_leaves.len();
    let test_leaves_len = test_leaves.len();
    assert_eq!(test_leaves_len, control_leaves_len);
    for (col, ref test_leaf) in test_leaves {
        let index = LeafIndex::new_max_depth(col);
        let &control_leaf = control_leaves.get(&index).unwrap();
        assert_eq!(test_leaf, control_leaf, "test leaf at column {col} does not match control");
    }

    // Make sure the inner nodes match, checking length first and then each individual leaf.
    let control_nodes_len = control.inner_nodes().count();
    let test_nodes_len = accumulated_nodes.len();
    assert_eq!(test_nodes_len, control_nodes_len);
    for (index, test_node) in accumulated_nodes.clone() {
        let control_node = control.get_inner_node(index);
        assert_eq!(test_node, control_node, "test node does not match control at {index:?}");
    }

    // After the last iteration of the above for loop, we should have the new root node actually
    // in two places: one in `accumulated_nodes`, and the other as the "next leaves" return from
    // `build_subtree()`. So let's check both!

    let control_root = control.get_inner_node(NodeIndex::root());

    // That for loop should have left us with only one leaf subtree...
    let [leaf_subtree]: [Vec<_>; 1] = leaf_subtrees.try_into().unwrap();
    // which itself contains only one 'leaf'...
    let [root_leaf]: [SubtreeLeaf; 1] = leaf_subtree.try_into().unwrap();
    // which matches the expected root.
    assert_eq!(control.root(), root_leaf.hash);

    // Likewise `accumulated_nodes` should contain a node at the root index...
    assert!(accumulated_nodes.contains_key(&NodeIndex::root()));
    // and it should match our actual root.
    let test_root = accumulated_nodes.get(&NodeIndex::root()).unwrap();
    assert_eq!(control_root, *test_root);
    // And of course the root we got from each place should match.
    assert_eq!(control.root(), root_leaf.hash);
}

/// The parallel version of `test_singlethreaded_subtree()`.
#[test]
#[cfg(feature = "concurrent")]
fn test_multithreaded_subtrees() {
    use rayon::prelude::*;

    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries(entries.clone()).unwrap();

    let mut accumulated_nodes: BTreeMap<NodeIndex, InnerNode> = Default::default();

    let PairComputations {
        leaves: mut leaf_subtrees,
        nodes: test_leaves,
    } = Smt::sorted_pairs_to_leaves(entries);

    for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
        let (nodes, subtrees): (Vec<BTreeMap<_, _>>, Vec<Vec<SubtreeLeaf>>) = leaf_subtrees
            .into_par_iter()
            .enumerate()
            .map(|(i, subtree)| {
                // Pre-assertions.
                assert!(
                    subtree.is_sorted(),
                    "subtree {i} at bottom-depth {current_depth} is not sorted",
                );
                assert!(
                    !subtree.is_empty(),
                    "subtree {i} at bottom-depth {current_depth} is empty!",
                );

                let (nodes, next_leaves) = Smt::build_subtree(subtree, current_depth);

                // Post-assertions.
                assert!(next_leaves.is_sorted());
                for (&index, test_node) in nodes.iter() {
                    let control_node = control.get_inner_node(index);
                    assert_eq!(
                        test_node, &control_node,
                        "depth {} subtree {}: test node does not match control at index {:?}",
                        current_depth, i, index,
                    );
                }

                (nodes, next_leaves)
            })
            .unzip();

        let mut all_leaves: Vec<SubtreeLeaf> = subtrees.into_iter().flatten().collect();
        leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut all_leaves).collect();

        accumulated_nodes.extend(nodes.into_iter().flatten());

        assert!(!leaf_subtrees.is_empty(), "on depth {current_depth}");
    }

    // Make sure the true leaves match, checking length first and then each individual leaf.
    let control_leaves: BTreeMap<_, _> = control.leaves().collect();
    let control_leaves_len = control_leaves.len();
    let test_leaves_len = test_leaves.len();
    assert_eq!(test_leaves_len, control_leaves_len);
    for (col, ref test_leaf) in test_leaves {
        let index = LeafIndex::new_max_depth(col);
        let &control_leaf = control_leaves.get(&index).unwrap();
        assert_eq!(test_leaf, control_leaf);
    }

    // Make sure the inner nodes match, checking length first and then each individual leaf.
    let control_nodes_len = control.inner_nodes().count();
    let test_nodes_len = accumulated_nodes.len();
    assert_eq!(test_nodes_len, control_nodes_len);
    for (index, test_node) in accumulated_nodes.clone() {
        let control_node = control.get_inner_node(index);
        assert_eq!(test_node, control_node, "test node does not match control at {index:?}");
    }

    // After the last iteration of the above for loop, we should have the new root node actually
    // in two places: one in `accumulated_nodes`, and the other as the "next leaves" return from
    // `build_subtree()`. So let's check both!

    let control_root = control.get_inner_node(NodeIndex::root());

    // That for loop should have left us with only one leaf subtree...
    let [leaf_subtree]: [_; 1] = leaf_subtrees.try_into().unwrap();
    // which itself contains only one 'leaf'...
    let [root_leaf]: [_; 1] = leaf_subtree.try_into().unwrap();
    // which matches the expected root.
    assert_eq!(control.root(), root_leaf.hash);

    // Likewise `accumulated_nodes` should contain a node at the root index...
    assert!(accumulated_nodes.contains_key(&NodeIndex::root()));
    // and it should match our actual root.
    let test_root = accumulated_nodes.get(&NodeIndex::root()).unwrap();
    assert_eq!(control_root, *test_root);
    // And of course the root we got from each place should match.
    assert_eq!(control.root(), root_leaf.hash);
}

#[test]
#[cfg(feature = "concurrent")]
fn test_with_entries_par() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries(entries.clone()).unwrap();

    let smt = Smt::with_entries_par(entries.clone()).unwrap();
    assert_eq!(smt.root(), control.root());
    assert_eq!(smt, control);
}
