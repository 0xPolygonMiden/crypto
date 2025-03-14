use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use miden_crypto::{
    Felt,
    hash::{
        blake::Blake3_256,
        rpo::{Rpo256, RpoDigest},
        rpx::{Rpx256, RpxDigest},
    },
};
use rand_utils::rand_value;
use winter_crypto::Hasher;

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

fn rpx256_2to1(c: &mut Criterion) {
    let v: [RpxDigest; 2] = [Rpx256::hash(&[1_u8]), Rpx256::hash(&[2_u8])];
    c.bench_function("RPX256 2-to-1 hashing (cached)", |bench| {
        bench.iter(|| Rpx256::merge(black_box(&v)))
    });

    c.bench_function("RPX256 2-to-1 hashing (random)", |bench| {
        bench.iter_batched(
            || {
                [
                    Rpx256::hash(&rand_value::<u64>().to_le_bytes()),
                    Rpx256::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Rpx256::merge(&state),
            BatchSize::SmallInput,
        )
    });
}

fn rpx256_sequential(c: &mut Criterion) {
    let v: [Felt; 100] = (0..100)
        .map(Felt::new)
        .collect::<Vec<Felt>>()
        .try_into()
        .expect("should not fail");
    c.bench_function("RPX256 sequential hashing (cached)", |bench| {
        bench.iter(|| Rpx256::hash_elements(black_box(&v)))
    });

    c.bench_function("RPX256 sequential hashing (random)", |bench| {
        bench.iter_batched(
            || {
                let v: [Felt; 100] = (0..100)
                    .map(|_| Felt::new(rand_value()))
                    .collect::<Vec<Felt>>()
                    .try_into()
                    .expect("should not fail");
                v
            },
            |state| Rpx256::hash_elements(&state),
            BatchSize::SmallInput,
        )
    });
}

fn blake3_2to1(c: &mut Criterion) {
    let v: [<Blake3_256 as Hasher>::Digest; 2] =
        [Blake3_256::hash(&[1_u8]), Blake3_256::hash(&[2_u8])];
    c.bench_function("Blake3 2-to-1 hashing (cached)", |bench| {
        bench.iter(|| Blake3_256::merge(black_box(&v)))
    });

    c.bench_function("Blake3 2-to-1 hashing (random)", |bench| {
        bench.iter_batched(
            || {
                [
                    Blake3_256::hash(&rand_value::<u64>().to_le_bytes()),
                    Blake3_256::hash(&rand_value::<u64>().to_le_bytes()),
                ]
            },
            |state| Blake3_256::merge(&state),
            BatchSize::SmallInput,
        )
    });
}

fn blake3_sequential(c: &mut Criterion) {
    let v: [Felt; 100] = (0..100)
        .map(Felt::new)
        .collect::<Vec<Felt>>()
        .try_into()
        .expect("should not fail");
    c.bench_function("Blake3 sequential hashing (cached)", |bench| {
        bench.iter(|| Blake3_256::hash_elements(black_box(&v)))
    });

    c.bench_function("Blake3 sequential hashing (random)", |bench| {
        bench.iter_batched(
            || {
                let v: [Felt; 100] = (0..100)
                    .map(|_| Felt::new(rand_value()))
                    .collect::<Vec<Felt>>()
                    .try_into()
                    .expect("should not fail");
                v
            },
            |state| Blake3_256::hash_elements(&state),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    hash_group,
    rpx256_2to1,
    rpx256_sequential,
    rpo256_2to1,
    rpo256_sequential,
    blake3_2to1,
    blake3_sequential
);
criterion_main!(hash_group);
