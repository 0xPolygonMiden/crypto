

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use miden_crypto::{hash::{Hasher, Digest}, HashFn, Felt, ElementHasher};
use rand_utils::rand_value;

fn rpo256_2to1(c: &mut Criterion) {
    let v: [Digest; 2] = [Hasher::hash(&[1u8]), Hasher::hash(&[2u8])];
    c.bench_function("RPO256 2-to-1 hashing (cached)", |bench| {
        bench.iter(|| Hasher::merge(black_box(&v)))
    });

    c.bench_function("RPO256 2-to-1 hashing (random)", |bench| {
        bench.iter_batched(
            || {
                [
                    Hasher::hash(&rand_value::<u64>().to_le_bytes()),
                    Hasher::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Hasher::merge(&state),
            BatchSize::SmallInput,
        )
    });
}

fn rpo256_sequential(c: &mut Criterion) {
    let v: [Felt; 100] = (0..100)
        .into_iter()
        .map(Felt::new)
        .collect::<Vec<Felt>>()
        .try_into()
        .expect("should not fail");
    c.bench_function("RPO256 sequential hashing (cached)", |bench| {
        bench.iter(|| Hasher::hash_elements(black_box(&v)))
    });

    c.bench_function("RPO256 sequential hashing (random)", |bench| {
        bench.iter_batched(
            || {
                let v: [Felt; 100] = (0..100)
                    .into_iter()
                    .map(|_| Felt::new(rand_value()))
                    .collect::<Vec<Felt>>()
                    .try_into()
                    .expect("should not fail");
                v
            },
            |state| Hasher::hash_elements(&state),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(hash_group, rpo256_sequential, rpo256_2to1);
criterion_main!(hash_group);