use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use miden_crypto::merkle::{MerkleStore, MerkleTree, NodeIndex, SimpleSmt};
use miden_crypto::Word;
use miden_crypto::{hash::rpo::RpoDigest, Felt};
use rand_utils::{rand_array, rand_value};

/// Since MerkleTree can only be created when a power-of-two number of elements is used, the sample
/// sizes are limited to that.
static BATCH_SIZES: [usize; 3] = [2usize.pow(4), 2usize.pow(7), 2usize.pow(10)];

/// Generates a random `RpoDigest`.
fn random_rpo_digest() -> RpoDigest {
    rand_array::<Felt, 4>().into()
}

/// Generates a random `Word`.
fn random_word() -> Word {
    rand_array::<Felt, 4>().into()
}

/// Generates a u64 in `0..range`.
fn random_index(range: u64) -> u64 {
    rand_value::<u64>() % range
}

/// Benchmarks getting an empty leaf from the SMT and MerkleStore backends.
fn get_empty_leaf_simplesmt(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_empty_leaf_simplesmt");

    let depth = 63u8;
    let size = 2u64.pow(depth as u32);

    // both SMT and the store are pre-populated with empty hashes, accessing these values is what is
    // being benchmarked here, so no values are inserted into the backends
    let smt = SimpleSmt::new(depth).unwrap();
    let store = MerkleStore::new();
    let root = smt.root();

    group.bench_function(BenchmarkId::new("SimpleSmt", depth), |b| {
        b.iter_batched(
            || random_index(size),
            |value| black_box(smt.get_node(&NodeIndex::new(depth, value))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("MerkleStore", depth), |b| {
        b.iter_batched(
            || random_index(size),
            |value| black_box(store.get_node(root, NodeIndex::new(depth, value))),
            BatchSize::SmallInput,
        )
    });
}

/// Benchmarks getting a leaf on Merkle trees and Merkle stores of varying power-of-two sizes.
fn get_leaf_merkletree(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_leaf_merkletree");

    let random_data_size = BATCH_SIZES.into_iter().max().unwrap();
    let random_data: Vec<RpoDigest> = (0..random_data_size).map(|_| random_rpo_digest()).collect();

    for size in BATCH_SIZES {
        let leaves = &random_data[..size];

        let mtree_leaves: Vec<Word> = leaves.iter().map(|v| v.into()).collect();
        let mtree = MerkleTree::new(mtree_leaves.clone()).unwrap();
        let store = MerkleStore::new().with_merkle_tree(mtree_leaves).unwrap();
        let depth = mtree.depth();
        let root = mtree.root();
        let size_u64 = size as u64;

        group.bench_function(BenchmarkId::new("MerkleTree", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(mtree.get_node(NodeIndex::new(depth, value))),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(BenchmarkId::new("MerkleStore", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(store.get_node(root, NodeIndex::new(depth, value))),
                BatchSize::SmallInput,
            )
        });
    }
}

/// Benchmarks getting a leaf on SMT and Merkle stores of varying power-of-two sizes.
fn get_leaf_simplesmt(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_leaf_simplesmt");

    let random_data_size = BATCH_SIZES.into_iter().max().unwrap();
    let random_data: Vec<RpoDigest> = (0..random_data_size).map(|_| random_rpo_digest()).collect();

    for size in BATCH_SIZES {
        let leaves = &random_data[..size];

        let smt_leaves = leaves
            .iter()
            .enumerate()
            .map(|(c, v)| (c.try_into().unwrap(), v.into()))
            .collect::<Vec<(u64, Word)>>();
        let smt = SimpleSmt::new(63)
            .unwrap()
            .with_leaves(smt_leaves.clone())
            .unwrap();
        let store = MerkleStore::new()
            .with_sparse_merkle_tree(smt_leaves)
            .unwrap();
        let depth = smt.depth();
        let root = smt.root();
        let size_u64 = size as u64;

        group.bench_function(BenchmarkId::new("SimpleSmt", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(smt.get_node(&NodeIndex::new(depth, value))),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(BenchmarkId::new("MerkleStore", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(store.get_node(root, NodeIndex::new(depth, value))),
                BatchSize::SmallInput,
            )
        });
    }
}

/// Benchmarks getting a node at half of the depth of an empty SMT and an empty Merkle store.
fn get_node_of_empty_simplesmt(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_node_of_empty_simplesmt");

    let depth = 63u8;
    let size = 2u64.pow(depth as u32);

    // both SMT and the store are pre-populated with the empty hashes, accessing the internal nodes
    // of these values is what is being benchmarked here, so no values are inserted into the
    // backends.
    let smt = SimpleSmt::new(depth).unwrap();
    let store = MerkleStore::new();
    let root = smt.root();
    let half_depth = depth / 2;

    group.bench_function(BenchmarkId::new("SimpleSmt", depth), |b| {
        b.iter_batched(
            || random_index(size),
            |value| black_box(smt.get_node(&NodeIndex::new(half_depth, value))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("MerkleStore", depth), |b| {
        b.iter_batched(
            || random_index(size),
            |value| black_box(store.get_node(root, NodeIndex::new(half_depth, value))),
            BatchSize::SmallInput,
        )
    });
}

/// Benchmarks getting a node at half of the depth of a Merkle tree and Merkle store of varying
/// power-of-two sizes.
fn get_node_merkletree(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_node_merkletree");

    let random_data_size = BATCH_SIZES.into_iter().max().unwrap();
    let random_data: Vec<RpoDigest> = (0..random_data_size).map(|_| random_rpo_digest()).collect();

    for size in BATCH_SIZES {
        let leaves = &random_data[..size];

        let mtree_leaves: Vec<Word> = leaves.iter().map(|v| v.into()).collect();
        let mtree = MerkleTree::new(mtree_leaves.clone()).unwrap();
        let store = MerkleStore::new().with_merkle_tree(mtree_leaves).unwrap();
        let half_depth = mtree.depth() / 2;
        let root = mtree.root();
        let size_u64 = size as u64;

        group.bench_function(BenchmarkId::new("MerkleTree", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(mtree.get_node(NodeIndex::new(half_depth, value))),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(BenchmarkId::new("MerkleStore", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(store.get_node(root, NodeIndex::new(half_depth, value))),
                BatchSize::SmallInput,
            )
        });
    }
}

/// Benchmarks getting a node at half the depth on SMT and Merkle stores of varying power-of-two
/// sizes.
fn get_node_simplesmt(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_node_simplesmt");

    let random_data_size = BATCH_SIZES.into_iter().max().unwrap();
    let random_data: Vec<RpoDigest> = (0..random_data_size).map(|_| random_rpo_digest()).collect();

    for size in BATCH_SIZES {
        let leaves = &random_data[..size];

        let smt_leaves = leaves
            .iter()
            .enumerate()
            .map(|(c, v)| (c.try_into().unwrap(), v.into()))
            .collect::<Vec<(u64, Word)>>();
        let smt = SimpleSmt::new(63)
            .unwrap()
            .with_leaves(smt_leaves.clone())
            .unwrap();
        let store = MerkleStore::new()
            .with_sparse_merkle_tree(smt_leaves)
            .unwrap();
        let root = smt.root();
        let size_u64 = size as u64;
        let half_depth = smt.depth() / 2;

        group.bench_function(BenchmarkId::new("SimpleSmt", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(smt.get_node(&NodeIndex::new(half_depth, value))),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(BenchmarkId::new("MerkleStore", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(store.get_node(root, NodeIndex::new(half_depth, value))),
                BatchSize::SmallInput,
            )
        });
    }
}

/// Benchmarks getting a path of a leaf on the Merkle tree and Merkle store backends.
fn get_leaf_path_merkletree(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_leaf_path_merkletree");

    let random_data_size = BATCH_SIZES.into_iter().max().unwrap();
    let random_data: Vec<RpoDigest> = (0..random_data_size).map(|_| random_rpo_digest()).collect();

    for size in BATCH_SIZES {
        let leaves = &random_data[..size];

        let mtree_leaves: Vec<Word> = leaves.iter().map(|v| v.into()).collect();
        let mtree = MerkleTree::new(mtree_leaves.clone()).unwrap();
        let store = MerkleStore::new().with_merkle_tree(mtree_leaves).unwrap();
        let depth = mtree.depth();
        let root = mtree.root();
        let size_u64 = size as u64;

        group.bench_function(BenchmarkId::new("MerkleTree", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(mtree.get_path(NodeIndex::new(depth, value))),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(BenchmarkId::new("MerkleStore", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(store.get_path(root, NodeIndex::new(depth, value))),
                BatchSize::SmallInput,
            )
        });
    }
}

/// Benchmarks getting a path of a leaf on the SMT and Merkle store backends.
fn get_leaf_path_simplesmt(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_leaf_path_simplesmt");

    let random_data_size = BATCH_SIZES.into_iter().max().unwrap();
    let random_data: Vec<RpoDigest> = (0..random_data_size).map(|_| random_rpo_digest()).collect();

    for size in BATCH_SIZES {
        let leaves = &random_data[..size];

        let smt_leaves = leaves
            .iter()
            .enumerate()
            .map(|(c, v)| (c.try_into().unwrap(), v.into()))
            .collect::<Vec<(u64, Word)>>();
        let smt = SimpleSmt::new(63)
            .unwrap()
            .with_leaves(smt_leaves.clone())
            .unwrap();
        let store = MerkleStore::new()
            .with_sparse_merkle_tree(smt_leaves)
            .unwrap();
        let depth = smt.depth();
        let root = smt.root();
        let size_u64 = size as u64;

        group.bench_function(BenchmarkId::new("SimpleSmt", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(smt.get_path(NodeIndex::new(depth, value))),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(BenchmarkId::new("MerkleStore", size), |b| {
            b.iter_batched(
                || random_index(size_u64),
                |value| black_box(store.get_path(root, NodeIndex::new(depth, value))),
                BatchSize::SmallInput,
            )
        });
    }
}

/// Benchmarks creation of the different storage backends
fn new(c: &mut Criterion) {
    let mut group = c.benchmark_group("new");

    let random_data_size = BATCH_SIZES.into_iter().max().unwrap();
    let random_data: Vec<RpoDigest> = (0..random_data_size).map(|_| random_rpo_digest()).collect();

    for size in BATCH_SIZES {
        let leaves = &random_data[..size];

        // MerkleTree constructor is optimized to work with vectors. Create a new copy of the data
        // and pass it to the benchmark function
        group.bench_function(BenchmarkId::new("MerkleTree::new", size), |b| {
            b.iter_batched(
                || leaves.iter().map(|v| v.into()).collect::<Vec<Word>>(),
                |l| black_box(MerkleTree::new(l)),
                BatchSize::SmallInput,
            )
        });

        // This could be done with `bench_with_input`, however to remove variables while comparing
        // with MerkleTree it is using `iter_batched`
        group.bench_function(
            BenchmarkId::new("MerkleStore::with_merkle_tree", size),
            |b| {
                b.iter_batched(
                    || leaves.iter().map(|v| v.into()).collect::<Vec<Word>>(),
                    |l| black_box(MerkleStore::new().with_merkle_tree(l)),
                    BatchSize::SmallInput,
                )
            },
        );

        group.bench_function(BenchmarkId::new("SimpleSmt::new", size), |b| {
            b.iter_batched(
                || {
                    leaves
                        .iter()
                        .enumerate()
                        .map(|(c, v)| (c.try_into().unwrap(), v.into()))
                        .collect::<Vec<(u64, Word)>>()
                },
                |l| black_box(SimpleSmt::new(63).unwrap().with_leaves(l)),
                BatchSize::SmallInput,
            )
        });

        group.bench_function(
            BenchmarkId::new("MerkleStore::with_sparse_merkle_tree", size),
            |b| {
                b.iter_batched(
                    || {
                        leaves
                            .iter()
                            .enumerate()
                            .map(|(c, v)| (c.try_into().unwrap(), v.into()))
                            .collect::<Vec<(u64, Word)>>()
                    },
                    |l| black_box(MerkleStore::new().with_sparse_merkle_tree(l)),
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

/// Benchmarks updating a leaf on MerkleTree and MerkleStore backends.
fn update_leaf_merkletree(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_leaf_merkletree");

    let random_data_size = BATCH_SIZES.into_iter().max().unwrap();
    let random_data: Vec<RpoDigest> = (0..random_data_size).map(|_| random_rpo_digest()).collect();

    for size in BATCH_SIZES {
        let leaves = &random_data[..size];

        let mtree_leaves: Vec<Word> = leaves.iter().map(|v| v.into()).collect();
        let mut mtree = MerkleTree::new(mtree_leaves.clone()).unwrap();
        let mut store = MerkleStore::new().with_merkle_tree(mtree_leaves).unwrap();
        let depth = mtree.depth();
        let root = mtree.root();
        let size_u64 = size as u64;

        group.bench_function(BenchmarkId::new("MerkleTree", size), |b| {
            b.iter_batched(
                || (random_index(size_u64), random_word()),
                |(index, value)| black_box(mtree.update_leaf(index, value)),
                BatchSize::SmallInput,
            )
        });

        let mut store_root = root;
        group.bench_function(BenchmarkId::new("MerkleStore", size), |b| {
            b.iter_batched(
                || (random_index(size_u64), random_word()),
                |(index, value)| {
                    // The MerkleTree automatically updates its internal root, the Store maintains
                    // the old root and adds the new one. Here we update the root to have a fair
                    // comparison
                    store_root = store
                        .set_node(root, NodeIndex::new(depth, index), value)
                        .unwrap()
                        .root;
                    black_box(store_root)
                },
                BatchSize::SmallInput,
            )
        });
    }
}

/// Benchmarks updating a leaf on SMT and MerkleStore backends.
fn update_leaf_simplesmt(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_leaf_simplesmt");

    let random_data_size = BATCH_SIZES.into_iter().max().unwrap();
    let random_data: Vec<RpoDigest> = (0..random_data_size).map(|_| random_rpo_digest()).collect();

    for size in BATCH_SIZES {
        let leaves = &random_data[..size];

        let smt_leaves = leaves
            .iter()
            .enumerate()
            .map(|(c, v)| (c.try_into().unwrap(), v.into()))
            .collect::<Vec<(u64, Word)>>();
        let mut smt = SimpleSmt::new(63)
            .unwrap()
            .with_leaves(smt_leaves.clone())
            .unwrap();
        let mut store = MerkleStore::new()
            .with_sparse_merkle_tree(smt_leaves)
            .unwrap();
        let depth = smt.depth();
        let root = smt.root();
        let size_u64 = size as u64;

        group.bench_function(BenchmarkId::new("SimpleSMT", size), |b| {
            b.iter_batched(
                || (random_index(size_u64), random_word()),
                |(index, value)| black_box(smt.update_leaf(index, value)),
                BatchSize::SmallInput,
            )
        });

        let mut store_root = root;
        group.bench_function(BenchmarkId::new("MerkleStore", size), |b| {
            b.iter_batched(
                || (random_index(size_u64), random_word()),
                |(index, value)| {
                    // The MerkleTree automatically updates its internal root, the Store maintains
                    // the old root and adds the new one. Here we update the root to have a fair
                    // comparison
                    store_root = store
                        .set_node(root, NodeIndex::new(depth, index), value)
                        .unwrap()
                        .root;
                    black_box(store_root)
                },
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(
    store_group,
    get_empty_leaf_simplesmt,
    get_leaf_merkletree,
    get_leaf_path_merkletree,
    get_leaf_path_simplesmt,
    get_leaf_simplesmt,
    get_node_merkletree,
    get_node_of_empty_simplesmt,
    get_node_simplesmt,
    new,
    update_leaf_merkletree,
    update_leaf_simplesmt,
);
criterion_main!(store_group);
