use std::{fmt::Debug, hint, mem, time::Duration};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use miden_crypto::{hash::rpo::RpoDigest, merkle::Smt, Felt, Word, ONE};
use rand_utils::prng_array;
use winter_utils::Randomizable;

// 2^0, 2^4, 2^8, 2^12, 2^16
const PAIR_COUNTS: [u64; 6] = [1, 16, 256, 4096, 65536, 1_048_576];

fn smt_parallel_subtree(c: &mut Criterion) {
    let mut seed = [0u8; 32];

    let mut group = c.benchmark_group("parallel-subtrees");

    for pair_count in PAIR_COUNTS {
        let bench_id = BenchmarkId::from_parameter(pair_count);
        group.bench_with_input(bench_id, &pair_count, |b, &pair_count| {
            b.iter_batched(
                || {
                    // Setup.
                    let entries: Vec<(RpoDigest, Word)> = (0..pair_count)
                        .map(|i| {
                            let count = pair_count as f64;
                            let idx = ((i as f64 / count) * (count)) as u64;
                            let key = RpoDigest::new([
                                generate_value(&mut seed),
                                ONE,
                                Felt::new(i),
                                Felt::new(idx),
                            ]);
                            let value = generate_word(&mut seed);
                            (key, value)
                        })
                        .collect();

                    let control = Smt::with_entries_sequential(entries.clone()).unwrap();
                    (entries, control)
                },
                |(entries, control)| {
                    // Benchmarked function.
                    let tree = Smt::with_entries(hint::black_box(entries)).unwrap();
                    assert_eq!(tree.root(), control.root());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = smt_subtree_group;
    config = Criterion::default()
        //.measurement_time(Duration::from_secs(960))
        .measurement_time(Duration::from_secs(60))
        .sample_size(10)
        .configure_from_args();
    targets = smt_parallel_subtree
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
