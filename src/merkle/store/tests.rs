use super::*;
use crate::{
    hash::rpo::Rpo256,
    merkle::{int_to_node, MerklePathSet},
    Felt, Word, WORD_SIZE, ZERO,
};

#[cfg(std)]
use std::error::Error;

const KEYS4: [u64; 4] = [0, 1, 2, 3];
const LEAVES4: [Word; 4] = [
    int_to_node(1),
    int_to_node(2),
    int_to_node(3),
    int_to_node(4),
];
const EMPTY: Word = [ZERO; WORD_SIZE];

#[test]
fn test_root_not_in_store() -> Result<(), MerkleError> {
    let mtree = MerkleTree::new(LEAVES4.to_vec())?;
    let store = MerkleStore::default().with_merkle_tree(LEAVES4)?;
    assert_eq!(
        store.get_node(LEAVES4[0], NodeIndex::new(mtree.depth(), 0)),
        Err(MerkleError::RootNotInStore(LEAVES4[0])),
        "Leaf 0 is not a root"
    );
    assert_eq!(
        store.get_path(LEAVES4[0], NodeIndex::new(mtree.depth(), 0)),
        Err(MerkleError::RootNotInStore(LEAVES4[0])),
        "Leaf 0 is not a root"
    );

    Ok(())
}

#[test]
fn test_merkle_tree() -> Result<(), MerkleError> {
    let mut store = MerkleStore::default();

    let mtree = MerkleTree::new(LEAVES4.to_vec())?;
    store.add_merkle_tree(LEAVES4.to_vec())?;

    // STORE LEAVES ARE CORRECT ==============================================================
    // checks the leaves in the store corresponds to the expected values
    assert_eq!(
        store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 0)),
        Ok(LEAVES4[0]),
        "node 0 must be in the tree"
    );
    assert_eq!(
        store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 1)),
        Ok(LEAVES4[1]),
        "node 1 must be in the tree"
    );
    assert_eq!(
        store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 2)),
        Ok(LEAVES4[2]),
        "node 2 must be in the tree"
    );
    assert_eq!(
        store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 3)),
        Ok(LEAVES4[3]),
        "node 3 must be in the tree"
    );

    // STORE LEAVES MATCH TREE ===============================================================
    // sanity check the values returned by the store and the tree
    assert_eq!(
        mtree.get_node(NodeIndex::new(mtree.depth(), 0)),
        store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 0)),
        "node 0 must be the same for both MerkleTree and MerkleStore"
    );
    assert_eq!(
        mtree.get_node(NodeIndex::new(mtree.depth(), 1)),
        store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 1)),
        "node 1 must be the same for both MerkleTree and MerkleStore"
    );
    assert_eq!(
        mtree.get_node(NodeIndex::new(mtree.depth(), 2)),
        store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 2)),
        "node 2 must be the same for both MerkleTree and MerkleStore"
    );
    assert_eq!(
        mtree.get_node(NodeIndex::new(mtree.depth(), 3)),
        store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 3)),
        "node 3 must be the same for both MerkleTree and MerkleStore"
    );

    // STORE MERKLE PATH MATCHS ==============================================================
    // assert the merkle path returned by the store is the same as the one in the tree
    let result = store
        .get_path(mtree.root(), NodeIndex::new(mtree.depth(), 0))
        .unwrap();
    assert_eq!(
        LEAVES4[0], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        mtree.get_path(NodeIndex::new(mtree.depth(), 0)),
        Ok(result.path),
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(mtree.root(), NodeIndex::new(mtree.depth(), 1))
        .unwrap();
    assert_eq!(
        LEAVES4[1], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        mtree.get_path(NodeIndex::new(mtree.depth(), 1)),
        Ok(result.path),
        "merkle path for index 1 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(mtree.root(), NodeIndex::new(mtree.depth(), 2))
        .unwrap();
    assert_eq!(
        LEAVES4[2], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        mtree.get_path(NodeIndex::new(mtree.depth(), 2)),
        Ok(result.path),
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(mtree.root(), NodeIndex::new(mtree.depth(), 3))
        .unwrap();
    assert_eq!(
        LEAVES4[3], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        mtree.get_path(NodeIndex::new(mtree.depth(), 3)),
        Ok(result.path),
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );

    Ok(())
}

#[test]
fn test_empty_roots() {
    let store = MerkleStore::default();
    let mut root = RpoDigest::new(EMPTY);

    for depth in 0..255 {
        root = Rpo256::merge(&[root; 2]);
        assert!(
            store.get_node(root.into(), NodeIndex::new(0, 0)).is_ok(),
            "The root of the empty tree of depth {depth} must be registered"
        );
    }
}

#[test]
fn test_leaf_paths_for_empty_trees() -> Result<(), MerkleError> {
    let store = MerkleStore::default();

    // Starts at 1 because leafs are not included in the store.
    // Ends at 64 because it is not possible to represent an index of a depth greater than 64,
    // because a u64 is used to index the leaf.
    for depth in 1..64 {
        let smt = SimpleSmt::new(depth)?;

        let index = NodeIndex::new(depth, 0);
        let store_path = store.get_path(smt.root(), index)?;
        let smt_path = smt.get_path(index)?;
        assert_eq!(
            store_path.value, EMPTY,
            "the leaf of an empty tree is always ZERO"
        );
        assert_eq!(
            store_path.path, smt_path,
            "the returned merkle path does not match the computed values"
        );
        assert_eq!(
            store_path.path.compute_root(depth.into(), EMPTY),
            smt.root(),
            "computed root from the path must match the empty tree root"
        );
    }

    Ok(())
}

#[test]
fn test_get_invalid_node() {
    let mut store = MerkleStore::default();
    let mtree = MerkleTree::new(LEAVES4.to_vec()).expect("creating a merkle tree must work");
    store
        .add_merkle_tree(LEAVES4.to_vec())
        .expect("adding a merkle tree to the store must work");
    let _ = store.get_node(mtree.root(), NodeIndex::new(mtree.depth(), 3));
}

#[test]
fn test_add_sparse_merkle_tree_one_level() -> Result<(), MerkleError> {
    let mut store = MerkleStore::default();
    let keys2: [u64; 2] = [0, 1];
    let leaves2: [Word; 2] = [int_to_node(1), int_to_node(2)];
    store.add_sparse_merkle_tree(keys2.into_iter().zip(leaves2.into_iter()))?;
    let smt = SimpleSmt::new(1)
        .unwrap()
        .with_leaves(keys2.into_iter().zip(leaves2.into_iter()))
        .unwrap();

    let idx = NodeIndex::new(1, 0);
    assert_eq!(smt.get_node(&idx).unwrap(), leaves2[0]);
    assert_eq!(
        store.get_node(smt.root(), idx).unwrap(),
        smt.get_node(&idx).unwrap()
    );

    let idx = NodeIndex::new(1, 1);
    assert_eq!(smt.get_node(&idx).unwrap(), leaves2[1]);
    assert_eq!(
        store.get_node(smt.root(), idx).unwrap(),
        smt.get_node(&idx).unwrap()
    );

    Ok(())
}

#[test]
fn test_sparse_merkle_tree() -> Result<(), MerkleError> {
    let mut store = MerkleStore::default();
    store.add_sparse_merkle_tree(KEYS4.into_iter().zip(LEAVES4.into_iter()))?;

    let smt = SimpleSmt::new(SimpleSmt::MAX_DEPTH)
        .unwrap()
        .with_leaves(KEYS4.into_iter().zip(LEAVES4.into_iter()))
        .unwrap();

    // STORE LEAVES ARE CORRECT ==============================================================
    // checks the leaves in the store corresponds to the expected values
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 0)),
        Ok(LEAVES4[0]),
        "node 0 must be in the tree"
    );
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 1)),
        Ok(LEAVES4[1]),
        "node 1 must be in the tree"
    );
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 2)),
        Ok(LEAVES4[2]),
        "node 2 must be in the tree"
    );
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 3)),
        Ok(LEAVES4[3]),
        "node 3 must be in the tree"
    );
    assert_eq!(
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 4)),
        Ok(EMPTY),
        "unmodified node 4 must be ZERO"
    );

    // STORE LEAVES MATCH TREE ===============================================================
    // sanity check the values returned by the store and the tree
    assert_eq!(
        smt.get_node(&NodeIndex::new(smt.depth(), 0)),
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 0)),
        "node 0 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        smt.get_node(&NodeIndex::new(smt.depth(), 1)),
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 1)),
        "node 1 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        smt.get_node(&NodeIndex::new(smt.depth(), 2)),
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 2)),
        "node 2 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        smt.get_node(&NodeIndex::new(smt.depth(), 3)),
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 3)),
        "node 3 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        smt.get_node(&NodeIndex::new(smt.depth(), 4)),
        store.get_node(smt.root(), NodeIndex::new(smt.depth(), 4)),
        "node 4 must be the same for both SparseMerkleTree and MerkleStore"
    );

    // STORE MERKLE PATH MATCHS ==============================================================
    // assert the merkle path returned by the store is the same as the one in the tree
    let result = store
        .get_path(smt.root(), NodeIndex::new(smt.depth(), 0))
        .unwrap();
    assert_eq!(
        LEAVES4[0], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        smt.get_path(NodeIndex::new(smt.depth(), 0)),
        Ok(result.path),
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(smt.root(), NodeIndex::new(smt.depth(), 1))
        .unwrap();
    assert_eq!(
        LEAVES4[1], result.value,
        "Value for merkle path at index 1 must match leaf value"
    );
    assert_eq!(
        smt.get_path(NodeIndex::new(smt.depth(), 1)),
        Ok(result.path),
        "merkle path for index 1 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(smt.root(), NodeIndex::new(smt.depth(), 2))
        .unwrap();
    assert_eq!(
        LEAVES4[2], result.value,
        "Value for merkle path at index 2 must match leaf value"
    );
    assert_eq!(
        smt.get_path(NodeIndex::new(smt.depth(), 2)),
        Ok(result.path),
        "merkle path for index 2 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(smt.root(), NodeIndex::new(smt.depth(), 3))
        .unwrap();
    assert_eq!(
        LEAVES4[3], result.value,
        "Value for merkle path at index 3 must match leaf value"
    );
    assert_eq!(
        smt.get_path(NodeIndex::new(smt.depth(), 3)),
        Ok(result.path),
        "merkle path for index 3 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(smt.root(), NodeIndex::new(smt.depth(), 4))
        .unwrap();
    assert_eq!(
        EMPTY, result.value,
        "Value for merkle path at index 4 must match leaf value"
    );
    assert_eq!(
        smt.get_path(NodeIndex::new(smt.depth(), 4)),
        Ok(result.path),
        "merkle path for index 4 must be the same for the MerkleTree and MerkleStore"
    );

    Ok(())
}

#[test]
fn test_add_merkle_paths() -> Result<(), MerkleError> {
    let mtree = MerkleTree::new(LEAVES4.to_vec())?;

    let i0 = 0;
    let p0 = mtree.get_path(NodeIndex::new(2, i0)).unwrap();

    let i1 = 1;
    let p1 = mtree.get_path(NodeIndex::new(2, i1)).unwrap();

    let i2 = 2;
    let p2 = mtree.get_path(NodeIndex::new(2, i2)).unwrap();

    let i3 = 3;
    let p3 = mtree.get_path(NodeIndex::new(2, i3)).unwrap();

    let paths = [
        (i0, LEAVES4[i0 as usize], p0),
        (i1, LEAVES4[i1 as usize], p1),
        (i2, LEAVES4[i2 as usize], p2),
        (i3, LEAVES4[i3 as usize], p3),
    ];

    let mut store = MerkleStore::default();
    store
        .add_merkle_paths(paths.clone())
        .expect("the valid paths must work");

    let depth = 2;
    let set = MerklePathSet::new(depth).with_paths(paths).unwrap();

    // STORE LEAVES ARE CORRECT ==============================================================
    // checks the leaves in the store corresponds to the expected values
    assert_eq!(
        store.get_node(set.root(), NodeIndex::new(set.depth(), 0)),
        Ok(LEAVES4[0]),
        "node 0 must be in the set"
    );
    assert_eq!(
        store.get_node(set.root(), NodeIndex::new(set.depth(), 1)),
        Ok(LEAVES4[1]),
        "node 1 must be in the set"
    );
    assert_eq!(
        store.get_node(set.root(), NodeIndex::new(set.depth(), 2)),
        Ok(LEAVES4[2]),
        "node 2 must be in the set"
    );
    assert_eq!(
        store.get_node(set.root(), NodeIndex::new(set.depth(), 3)),
        Ok(LEAVES4[3]),
        "node 3 must be in the set"
    );

    // STORE LEAVES MATCH SET ================================================================
    // sanity check the values returned by the store and the set
    assert_eq!(
        set.get_node(NodeIndex::new(set.depth(), 0)),
        store.get_node(set.root(), NodeIndex::new(set.depth(), 0)),
        "node 0 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        set.get_node(NodeIndex::new(set.depth(), 1)),
        store.get_node(set.root(), NodeIndex::new(set.depth(), 1)),
        "node 1 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        set.get_node(NodeIndex::new(set.depth(), 2)),
        store.get_node(set.root(), NodeIndex::new(set.depth(), 2)),
        "node 2 must be the same for both SparseMerkleTree and MerkleStore"
    );
    assert_eq!(
        set.get_node(NodeIndex::new(set.depth(), 3)),
        store.get_node(set.root(), NodeIndex::new(set.depth(), 3)),
        "node 3 must be the same for both SparseMerkleTree and MerkleStore"
    );

    // STORE MERKLE PATH MATCHS ==============================================================
    // assert the merkle path returned by the store is the same as the one in the set
    let result = store
        .get_path(set.root(), NodeIndex::new(set.depth(), 0))
        .unwrap();
    assert_eq!(
        LEAVES4[0], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        set.get_path(NodeIndex::new(set.depth(), 0)),
        Ok(result.path),
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(set.root(), NodeIndex::new(set.depth(), 1))
        .unwrap();
    assert_eq!(
        LEAVES4[1], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        set.get_path(NodeIndex::new(set.depth(), 1)),
        Ok(result.path),
        "merkle path for index 1 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(set.root(), NodeIndex::new(set.depth(), 2))
        .unwrap();
    assert_eq!(
        LEAVES4[2], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        set.get_path(NodeIndex::new(set.depth(), 2)),
        Ok(result.path),
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );

    let result = store
        .get_path(set.root(), NodeIndex::new(set.depth(), 3))
        .unwrap();
    assert_eq!(
        LEAVES4[3], result.value,
        "Value for merkle path at index 0 must match leaf value"
    );
    assert_eq!(
        set.get_path(NodeIndex::new(set.depth(), 3)),
        Ok(result.path),
        "merkle path for index 0 must be the same for the MerkleTree and MerkleStore"
    );

    Ok(())
}

#[test]
fn wont_open_to_different_depth_root() {
    let empty = EmptySubtreeRoots::empty_hashes(64);
    let a = [Felt::new(1); 4];
    let b = [Felt::new(2); 4];

    // Compute the root for a different depth. We cherry-pick this specific depth to prevent a
    // regression to a bug in the past that allowed the user to fetch a node at a depth lower than
    // the inserted path of a Merkle tree.
    let mut root = Rpo256::merge(&[a.into(), b.into()]);
    for depth in (1..=63).rev() {
        root = Rpo256::merge(&[root, empty[depth]]);
    }
    let root = Word::from(root);

    // For this example, the depth of the Merkle tree is 1, as we have only two leaves. Here we
    // attempt to fetch a node on the maximum depth, and it should fail because the root shouldn't
    // exist for the set.
    let store = MerkleStore::default().with_merkle_tree([a, b]).unwrap();
    let index = NodeIndex::root();
    let err = store.get_node(root, index).err().unwrap();
    assert_eq!(err, MerkleError::RootNotInStore(root));
}

#[test]
fn store_path_opens_from_leaf() {
    let a = [Felt::new(1); 4];
    let b = [Felt::new(2); 4];
    let c = [Felt::new(3); 4];
    let d = [Felt::new(4); 4];
    let e = [Felt::new(5); 4];
    let f = [Felt::new(6); 4];
    let g = [Felt::new(7); 4];
    let h = [Felt::new(8); 4];

    let i = Rpo256::merge(&[a.into(), b.into()]);
    let j = Rpo256::merge(&[c.into(), d.into()]);
    let k = Rpo256::merge(&[e.into(), f.into()]);
    let l = Rpo256::merge(&[g.into(), h.into()]);

    let m = Rpo256::merge(&[i.into(), j.into()]);
    let n = Rpo256::merge(&[k.into(), l.into()]);

    let root = Rpo256::merge(&[m.into(), n.into()]);

    let store = MerkleStore::default()
        .with_merkle_tree([a, b, c, d, e, f, g, h])
        .unwrap();
    let path = store
        .get_path(root.into(), NodeIndex::new(3, 1))
        .unwrap()
        .path;

    let expected = MerklePath::new([a.into(), j.into(), n.into()].to_vec());
    assert_eq!(path, expected);
}

#[test]
fn test_set_node() -> Result<(), MerkleError> {
    let mtree = MerkleTree::new(LEAVES4.to_vec())?;
    let mut store = MerkleStore::default().with_merkle_tree(LEAVES4)?;
    let value = int_to_node(42);
    let index = NodeIndex::new(mtree.depth(), 0);
    let new_root = store.set_node(mtree.root(), index, value)?.root;
    assert_eq!(
        store.get_node(new_root, index),
        Ok(value),
        "Value must have changed"
    );

    Ok(())
}

#[test]
fn test_constructors() -> Result<(), MerkleError> {
    let store = MerkleStore::new().with_merkle_tree(LEAVES4)?;
    let mtree = MerkleTree::new(LEAVES4.to_vec())?;

    let depth = mtree.depth();
    let leaves = 2u64.pow(depth.into());
    for index in 0..leaves {
        let index = NodeIndex::new(depth, index);
        let value_path = store.get_path(mtree.root(), index)?;
        assert_eq!(mtree.get_path(index)?, value_path.path);
    }

    let store = MerkleStore::default()
        .with_sparse_merkle_tree(KEYS4.into_iter().zip(LEAVES4.into_iter()))?;
    let smt = SimpleSmt::new(SimpleSmt::MAX_DEPTH)
        .unwrap()
        .with_leaves(KEYS4.into_iter().zip(LEAVES4.into_iter()))
        .unwrap();
    let depth = smt.depth();

    for key in KEYS4 {
        let index = NodeIndex::new(depth, key);
        let value_path = store.get_path(smt.root(), index)?;
        assert_eq!(smt.get_path(index)?, value_path.path);
    }

    let d = 2;
    let paths = [
        (0, LEAVES4[0], mtree.get_path(NodeIndex::new(d, 0)).unwrap()),
        (1, LEAVES4[1], mtree.get_path(NodeIndex::new(d, 1)).unwrap()),
        (2, LEAVES4[2], mtree.get_path(NodeIndex::new(d, 2)).unwrap()),
        (3, LEAVES4[3], mtree.get_path(NodeIndex::new(d, 3)).unwrap()),
    ];

    let store1 = MerkleStore::default().with_merkle_paths(paths.clone())?;
    let store2 = MerkleStore::default()
        .with_merkle_path(0, LEAVES4[0], mtree.get_path(NodeIndex::new(d, 0))?)?
        .with_merkle_path(1, LEAVES4[1], mtree.get_path(NodeIndex::new(d, 1))?)?
        .with_merkle_path(2, LEAVES4[2], mtree.get_path(NodeIndex::new(d, 2))?)?
        .with_merkle_path(3, LEAVES4[3], mtree.get_path(NodeIndex::new(d, 3))?)?;
    let set = MerklePathSet::new(d).with_paths(paths).unwrap();

    for key in [0, 1, 2, 3] {
        let index = NodeIndex::new(d, key);
        let value_path1 = store1.get_path(set.root(), index)?;
        let value_path2 = store2.get_path(set.root(), index)?;
        assert_eq!(value_path1, value_path2);

        let index = NodeIndex::new(d, key);
        assert_eq!(set.get_path(index)?, value_path1.path);
    }

    Ok(())
}

#[cfg(std)]
#[test]
fn test_serialization() -> Result<(), Box<dyn Error>> {
    let original = MerkleStore::new().with_merkle_tree(LEAVES4)?;
    let decoded = MerkleStore::read_from_bytes(&original.to_bytes())?;
    assert_eq!(original, decoded);
    Ok(())
}
