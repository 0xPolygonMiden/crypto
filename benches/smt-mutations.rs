use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use miden_crypto::{
    merkle::{LeafIndex, SimpleSmt},
    Felt, Word, EMPTY_WORD,
};
use rand::{prelude::SliceRandom, rngs::StdRng, Rng, SeedableRng};

const DEPTH: u8 = 64;

fn benchmark_apply_mutations(c: &mut Criterion) {
    let mut group = c.benchmark_group("apply_mutations");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(300));

    // Fixed seed for reproducibility
    let rng_seed = 42;
    let mut rng = StdRng::seed_from_u64(rng_seed);

    // Benchmark for various mutation set sizes
    for &mutation_count in &[1_000, 100_000] {
        group.bench_with_input(
            BenchmarkId::new("SimpleSmt: apply_mutations", mutation_count),
            &mutation_count,
            |b, &mutation_count| {
                // Batch-based benchmarking
                b.iter_batched(
                    || {
                        const REMOVAL_PROBABILITY: f64 = 0.2;

                        // Fill tree with 10x more initial elements
                        let initial_fill_count = mutation_count * 10;

                        // Initialize the tree with initial random values
                        let initial_kv_pairs = generate_kv_pairs(&mut rng, initial_fill_count);
                        let smt = SimpleSmt::<DEPTH>::with_leaves(initial_kv_pairs.iter().cloned())
                            .unwrap();

                        // Select and change a half of pairs from the filled tree (values to be
                        // updated or removed with given probability)
                        let mut mutation_kv_pairs: Vec<_> = initial_kv_pairs
                            .choose_multiple(&mut rng, mutation_count / 2)
                            .cloned()
                            .map(|(key, _value)| {
                                let value = if rng.gen_bool(REMOVAL_PROBABILITY) {
                                    EMPTY_WORD
                                } else {
                                    generate_word(&mut rng)
                                };

                                (key, value)
                            })
                            .collect();

                        // Append another half of new values (values to be added)
                        for _ in 0..mutation_count / 2 {
                            mutation_kv_pairs.push((rng.gen(), generate_word(&mut rng)));
                        }

                        // Compute mutations
                        let mutations = smt.compute_mutations(
                            mutation_kv_pairs
                                .into_iter()
                                .map(|(key, value)| (LeafIndex::new(key).unwrap(), value)),
                        );

                        (smt, mutations)
                    },
                    |(mut smt, mutations)| {
                        // Apply mutations in the benchmark to measure execution time
                        smt.apply_mutations(mutations).unwrap();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_apply_mutations);
criterion_main!(benches);

// HELPER FUNCTIONS
// =================================================================================================

/// Helper function to generate random `(u64, Word)` key-value pairs
fn generate_kv_pairs(rng: &mut StdRng, count: usize) -> Vec<(u64, Word)> {
    (0..count)
        .map(|_| {
            let key = rng.gen();
            let value = generate_word(rng);

            (key, value)
        })
        .collect()
}

/// Helper function to generate random `Word`
fn generate_word(rng: &mut StdRng) -> Word {
    // Random Word value
    [
        Felt::new(rng.gen()),
        Felt::new(rng.gen()),
        Felt::new(rng.gen()),
        Felt::new(rng.gen()),
    ]
}
