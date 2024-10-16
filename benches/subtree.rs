use std::{collections::BTreeMap, sync::Arc, time::Duration};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use miden_crypto::{
    hash::rpo::RpoDigest,
    merkle::{NodeIndex, NodeSubtreeComputer, Smt, SparseMerkleTree},
    Felt, Word, ONE,
};

const SUBTREE_INTERVAL: u8 = 8;

fn setup_subtree8(tree_size: u64) -> (Smt, NodeIndex, Arc<BTreeMap<RpoDigest, Word>>, RpoDigest) {
    let entries: BTreeMap<RpoDigest, Word> = (0..tree_size)
        .into_iter()
        .map(|i| {
            let leaf_index = u64::MAX / (i + 1);
            let key = RpoDigest::new([ONE, ONE, Felt::new(i), Felt::new(leaf_index)]);
            let value = [ONE, ONE, ONE, Felt::new(i)];
            (key, value)
        })
        .collect();
    let control = Smt::with_entries(entries.clone()).unwrap();
    let subtree = entries
        .keys()
        .map(|key| {
            let index_for_key = NodeIndex::from(Smt::key_to_leaf_index(key));
            index_for_key.parent_n(SUBTREE_INTERVAL)
        })
        .next()
        .unwrap();
    let control_hash = control.get_inner_node(subtree).hash();
    (Smt::new(), subtree, Arc::new(entries), control_hash)
}

fn bench_subtree8(
    (smt, subtree, entries, control_hash): (
        Smt,
        NodeIndex,
        Arc<BTreeMap<RpoDigest, Word>>,
        RpoDigest,
    ),
) {
    let mut state = NodeSubtreeComputer::with_smt(&smt, Default::default(), entries);
    let hash = state.get_or_make_hash(subtree);
    assert_eq!(control_hash, hash);
}

fn smt_subtree8(c: &mut Criterion) {
    let mut group = c.benchmark_group("subtree8");

    group.measurement_time(Duration::from_secs(360));
    group.sample_size(30);

    for &tree_size in [32, 128, 512, 1024, 8192].iter() {
        let bench_id = BenchmarkId::from_parameter(tree_size);
        //group.throughput(Throughput::Elements(tree_size));
        group.bench_with_input(bench_id, &tree_size, |bench, &tree_size| {
            bench.iter_batched(|| setup_subtree8(tree_size), bench_subtree8, BatchSize::SmallInput);
        });
    }

    group.finish();
}

criterion_group!(subtree_group, smt_subtree8);
criterion_main!(subtree_group);
