use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use miden_crypto::{
    hash::rpo::{Rpo256, RpoDigest},
    Felt,
};
use rand_utils::rand_value;

fn rpo256_2to1(c: &mut Criterion) {
    let v: [RpoDigest; 2] = [Rpo256::hash(&[1_u8]), Rpo256::hash(&[2_u8])];
    c.bench_function("RPO256 2-to-1 hashing (cached)", |bench| {
        bench.iter(|| Rpo256::merge(black_box(&v)))
    });

    c.bench_function("RPO256 2-to-1 hashing (random)", |bench| {
        bench.iter_batched(
            || {
                [
                    Rpo256::hash(&rand_value::<u64>().to_le_bytes()),
                    Rpo256::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Rpo256::merge(&state),
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
        bench.iter(|| Rpo256::hash_elements(black_box(&v)))
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
            |state| Rpo256::hash_elements(&state),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(hash_group, rpo256_sequential, rpo256_2to1);
criterion_main!(hash_group);
