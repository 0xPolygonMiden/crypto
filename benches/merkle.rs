use std::{hint, mem, time::Duration};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use miden_crypto::{merkle::MerkleTree, Felt, Word, ONE};
use rand_utils::prng_array;

fn balanced_merkle_even(c: &mut Criterion) {
    c.bench_function("balanced-merkle-even", |b| {
        b.iter_batched(
            || {
                let entries: Vec<Word> =
                    (0..256).map(|i| [Felt::new(i), ONE, ONE, Felt::new(i)]).collect();
                assert_eq!(entries.len(), 256);
                entries
            },
            |leaves| {
                let tree = MerkleTree::new(hint::black_box(leaves)).unwrap();
                assert_eq!(tree.depth(), 8);
            },
            BatchSize::SmallInput,
        );
    });
}

fn balanced_merkle_rand(c: &mut Criterion) {
    let mut seed = [0u8; 32];
    c.bench_function("balanced-merkle-rand", |b| {
        b.iter_batched(
            || {
                let entries: Vec<Word> = (0..256).map(|_| generate_word(&mut seed)).collect();
                assert_eq!(entries.len(), 256);
                entries
            },
            |leaves| {
                let tree = MerkleTree::new(hint::black_box(leaves)).unwrap();
                assert_eq!(tree.depth(), 8);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = smt_subtree_group;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(20))
        .configure_from_args();
    targets = balanced_merkle_even, balanced_merkle_rand
}
criterion_main!(smt_subtree_group);

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn generate_word(seed: &mut [u8; 32]) -> Word {
    mem::swap(seed, &mut prng_array(*seed));
    let nums: [u64; 4] = prng_array(*seed);
    [Felt::new(nums[0]), Felt::new(nums[1]), Felt::new(nums[2]), Felt::new(nums[3])]
}
