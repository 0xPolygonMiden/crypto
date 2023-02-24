use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use miden_crypto::{
    hash::{
        blake::Blake3_256,
        rpo::{Rpo256, RpoDigest},
    },
    Felt,
};
use rand_utils::{rand_array, rand_vector};
use winter_crypto::Hasher;

static BATCH_SIZES: [usize; 5] = [16, 32, 64, 100, 256];

fn hash_2to1(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge");

    // Try to measure a single iteration of the hash function. This is intended as a sanity check
    // but not reliable for optimization, since a single iteration is too fast and the measuring
    // interferes with its result.
    //
    // Also note that the single entry case does not have a loop, so this is not directly
    // comparable to the iterations bellow.
    let s: [RpoDigest; 2] = [Rpo256::hash(&[1_u8]), Rpo256::hash(&[2_u8])];
    group.bench_with_input(BenchmarkId::new("RPO256", 1), &s, |b, i| {
        b.iter(|| {
            Rpo256::merge(black_box(&i));
        })
    });

    let s2: [<Blake3_256 as Hasher>::Digest; 2] =
        [Blake3_256::hash(&[1_u8]), Blake3_256::hash(&[2_u8])];
    group.bench_with_input(BenchmarkId::new("Blake3_256", 1), &s2, |b, i| {
        b.iter(|| {
            Blake3_256::merge(black_box(&i));
        })
    });

    // Benchmark `merge` in a hot loop with varying number of elements, the goal is to spend more
    // time in the hashing function so that the cost of measuring it will dissipiate in the
    // background and give better view of the algorithms performance.
    for size in BATCH_SIZES {
        let v: Vec<[RpoDigest; 2]> = (0..size)
            .map(|_| {
                let left = rand_array::<Felt, 4>().into();
                let right = rand_array::<Felt, 4>().into();
                [left, right]
            })
            .collect();

        group.bench_with_input(BenchmarkId::new(format!("RPO256"), size), &v, |b, i| {
            b.iter(|| {
                for pair in i {
                    Rpo256::merge(black_box(&pair));
                }
            })
        });

        let v2: Vec<[<Blake3_256 as Hasher>::Digest; 2]> =
            v.iter().map(|[l, r]| [l.as_bytes().into(), r.as_bytes().into()]).collect();
        group.bench_with_input(BenchmarkId::new(format!("Blake3_256"), size), &v2, |b, i| {
            b.iter(|| {
                for pair in i {
                    Blake3_256::merge(black_box(&pair));
                }
            })
        });
    }
}

fn hash_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_elements");

    for size in BATCH_SIZES {
        let v: Vec<Felt> = rand_vector(size);

        group.bench_with_input(BenchmarkId::new(format!("RPO256"), size), &v, |b, i| {
            b.iter(|| Rpo256::hash_elements(&i))
        });

        group.bench_with_input(BenchmarkId::new(format!("Blake3_256"), size), &v, |b, i| {
            b.iter(|| Blake3_256::hash_elements(&i))
        });
    }
}

criterion_group!(hash_group, hash_2to1, hash_sequential);
criterion_main!(hash_group);
