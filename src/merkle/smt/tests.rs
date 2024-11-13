use alloc::{collections::BTreeMap, vec::Vec};

use super::{PairComputations, SmtLeaf, SparseMerkleTree, SubtreeLeaf, SubtreeLeavesIter};
use crate::{hash::rpo::RpoDigest, merkle::Smt, Felt, Word, ONE};

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
