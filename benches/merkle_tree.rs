use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use miden_crypto::{merkle::MerkleTree, Word};
use rand_utils::rand_array;
pub use winter_math::fields::f64::BaseElement as Felt;

static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

pub fn merkle_tree_construction(c: &mut Criterion) {
    let mut merkle_group = c.benchmark_group("MerkleTree");

    for size in &BATCH_SIZES {
        let data: Vec<Word> = (0..*size).map(|_| rand_array::<Felt, 4>()).collect();

        merkle_group.bench_with_input(BenchmarkId::new("construction", size), &data, |b, i| {
            b.iter(|| MerkleTree::new(i))
        });
    }
}

criterion_group!(merkle_tree, merkle_tree_construction);
criterion_main!(merkle_tree);
