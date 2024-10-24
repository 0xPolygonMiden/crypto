use std::{fmt::Debug, hint, mem, time::Duration};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use miden_crypto::{
    hash::rpo::RpoDigest,
    merkle::{NodeIndex, Smt, SmtLeaf, SMT_DEPTH},
    Felt, Word, ONE,
};
use rand_utils::prng_array;
use winter_utils::Randomizable;

fn smt_subtree_even(c: &mut Criterion) {
    let mut seed = [0u8; 32];

    let mut group = c.benchmark_group("subtree8-even");

    for pair_count in (64..=256).step_by(64) {
        let bench_id = BenchmarkId::from_parameter(pair_count);
        group.bench_with_input(bench_id, &pair_count, |b, &pair_count| {
            b.iter_batched(
                || {
                    // Setup.
                    let entries: Vec<(RpoDigest, Word)> = (0..pair_count)
                        .map(|n| {
                            // A single depth-8 subtree can have a maximum of 255 leaves.
                            let leaf_index = (n / pair_count) * 255;
                            let key = RpoDigest::new([
                                generate_value(&mut seed),
                                ONE,
                                Felt::new(n),
                                Felt::new(leaf_index),
                            ]);
                            let value = generate_word(&mut seed);
                            (key, value)
                        })
                        .collect();

                    let mut leaves: Vec<_> = entries
                        .iter()
                        .map(|(key, value)| {
                            let leaf = SmtLeaf::new_single(*key, *value);
                            let col = NodeIndex::from(leaf.index()).value();
                            let hash = leaf.hash();
                            (col, hash)
                        })
                        .collect();
                    leaves.sort();
                    leaves
                },
                |leaves| {
                    // Benchmarked function.
                    let subtree =
                        Smt::build_subtree(hint::black_box(leaves), hint::black_box(SMT_DEPTH));
                    assert!(!subtree.is_empty());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

fn smt_subtree_random(c: &mut Criterion) {
    let mut seed = [0u8; 32];

    let mut group = c.benchmark_group("subtree8-rand");

    for pair_count in (64..=256).step_by(64) {
        let bench_id = BenchmarkId::from_parameter(pair_count);
        group.bench_with_input(bench_id, &pair_count, |b, &pair_count| {
            b.iter_batched(
                || {
                    // Setup.
                    let entries: Vec<(RpoDigest, Word)> = (0..pair_count)
                        .map(|i| {
                            let leaf_index: u8 = generate_value(&mut seed);
                            let key = RpoDigest::new([
                                ONE,
                                ONE,
                                Felt::new(i),
                                Felt::new(leaf_index as u64),
                            ]);
                            let value = generate_word(&mut seed);
                            (key, value)
                        })
                        .collect();

                    let mut leaves: Vec<_> = entries
                        .iter()
                        .map(|(key, value)| {
                            let leaf = SmtLeaf::new_single(*key, *value);
                            let col = NodeIndex::from(leaf.index()).value();
                            let hash = leaf.hash();
                            (col, hash)
                        })
                        .collect();
                    leaves.sort();
                    let before = leaves.len();
                    leaves.dedup();
                    let after = leaves.len();
                    assert_eq!(before, after);
                    leaves
                },
                |leaves| {
                    let subtree =
                        Smt::build_subtree(hint::black_box(leaves), hint::black_box(SMT_DEPTH));
                    assert!(!subtree.is_empty());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = smt_subtree_group;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(40))
        .sample_size(60)
        .configure_from_args();
    targets = smt_subtree_even, smt_subtree_random
}
criterion_main!(smt_subtree_group);

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn generate_value<T: Copy + Debug + Randomizable>(seed: &mut [u8; 32]) -> T {
    mem::swap(seed, &mut prng_array(*seed));
    let value: [T; 1] = rand_utils::prng_array(*seed);
    value[0]
}

fn generate_word(seed: &mut [u8; 32]) -> Word {
    mem::swap(seed, &mut prng_array(*seed));
    let nums: [u64; 4] = prng_array(*seed);
    [Felt::new(nums[0]), Felt::new(nums[1]), Felt::new(nums[2]), Felt::new(nums[3])]
}
