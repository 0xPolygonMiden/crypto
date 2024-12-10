use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use miden_crypto::dsa::{
    rpo_falcon512::SecretKey as FalconSecretKey, rpo_stark::SecretKey as RpoStarkSecretKey,
};
use rand_utils::rand_array;

fn key_gen_falcon(c: &mut Criterion) {
    c.bench_function("Falcon public key generation", |bench| {
        bench.iter_batched(|| FalconSecretKey::new(), |sk| sk.public_key(), BatchSize::SmallInput)
    });

    c.bench_function("Falcon secret key generation", |bench| {
        bench.iter_batched(|| {}, |_| FalconSecretKey::new(), BatchSize::SmallInput)
    });
}

fn key_gen_rpo_stark(c: &mut Criterion) {
    c.bench_function("RPO-STARK public key generation", |bench| {
        bench.iter_batched(
            || RpoStarkSecretKey::random(),
            |sk| sk.public_key(),
            BatchSize::SmallInput,
        )
    });

    c.bench_function("RPO-STARK secret key generation", |bench| {
        bench.iter_batched(|| {}, |_| RpoStarkSecretKey::random(), BatchSize::SmallInput)
    });
}

fn signature_gen_falcon(c: &mut Criterion) {
    c.bench_function("Falcon signature generation", |bench| {
        bench.iter_batched(
            || (FalconSecretKey::new(), rand_array().into()),
            |(sk, msg)| sk.sign(msg),
            BatchSize::SmallInput,
        )
    });
}

fn signature_gen_rpo_stark(c: &mut Criterion) {
    c.bench_function("RPO-STARK signature generation", |bench| {
        bench.iter_batched(
            || (RpoStarkSecretKey::random(), rand_array().into()),
            |(sk, msg)| sk.sign(msg),
            BatchSize::SmallInput,
        )
    });
}

fn signature_ver_falcon(c: &mut Criterion) {
    c.bench_function("Falcon signature verification", |bench| {
        bench.iter_batched(
            || {
                let sk = FalconSecretKey::new();
                let msg = rand_array().into();
                (sk.public_key(), msg, sk.sign(msg))
            },
            |(pk, msg, sig)| pk.verify(msg, &sig),
            BatchSize::SmallInput,
        )
    });
}

fn signature_ver_rpo_stark(c: &mut Criterion) {
    c.bench_function("RPO-STARK signature verification", |bench| {
        bench.iter_batched(
            || {
                let sk = RpoStarkSecretKey::random();
                let msg = rand_array().into();
                (sk.public_key(), msg, sk.sign(msg))
            },
            |(pk, msg, sig)| pk.verify(msg, &sig),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    dsa_group,
    key_gen_falcon,
    key_gen_rpo_stark,
    signature_gen_falcon,
    signature_gen_rpo_stark,
    signature_ver_falcon,
    signature_ver_rpo_stark
);
criterion_main!(dsa_group);
