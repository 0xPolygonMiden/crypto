use core::mem::swap;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use miden_crypto::{merkle::SimpleSmt, Felt, Word};
use rand_utils::prng_array;

fn smt_rpo(c: &mut Criterion) {
    // setup trees

    let mut seed = [0u8; 32];
    let mut trees = vec![];

    for depth in 14..=20 {
        let leaves = ((1 << depth) - 1) as u64;
        for count in [1, leaves / 2, leaves] {
            let entries: Vec<_> = (0..count)
                .map(|i| {
                    let word = generate_word(&mut seed);
                    (i, word)
                })
                .collect();
            let tree = SimpleSmt::new(depth).unwrap().with_leaves(entries).unwrap();
            trees.push(tree);
        }
    }

    let leaf = generate_word(&mut seed);

    // benchmarks

    let mut insert = c.benchmark_group(format!("smt update_leaf"));

    for tree in trees.iter_mut() {
        let depth = tree.depth();
        let count = tree.leaves_count() as u64;
        let key = count >> 2;
        insert.bench_with_input(
            format!("simple smt(depth:{depth},count:{count})"),
            &(key, leaf),
            |b, (key, leaf)| {
                b.iter(|| {
                    tree.update_leaf(black_box(*key), black_box(*leaf)).unwrap();
                });
            },
        );
    }

    insert.finish();

    let mut path = c.benchmark_group(format!("smt get_leaf_path"));

    for tree in trees.iter_mut() {
        let depth = tree.depth();
        let count = tree.leaves_count() as u64;
        let key = count >> 2;
        path.bench_with_input(
            format!("simple smt(depth:{depth},count:{count})"),
            &key,
            |b, key| {
                b.iter(|| {
                    tree.get_leaf_path(black_box(*key)).unwrap();
                });
            },
        );
    }

    path.finish();
}

criterion_group!(smt_group, smt_rpo);
criterion_main!(smt_group);

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn generate_word(seed: &mut [u8; 32]) -> Word {
    swap(seed, &mut prng_array(*seed));
    let nums: [u64; 4] = prng_array(*seed);
    [
        Felt::new(nums[0]),
        Felt::new(nums[1]),
        Felt::new(nums[2]),
        Felt::new(nums[3]),
    ]
}
