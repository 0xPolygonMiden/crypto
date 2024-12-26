use std::time::Instant;

use clap::Parser;
use miden_crypto::{
    hash::rpo::{Rpo256, RpoDigest},
    merkle::{MerkleError, Smt},
    Felt, Word, EMPTY_WORD, ONE,
};
use rand::{prelude::IteratorRandom, thread_rng, Rng};
use rand_utils::rand_value;

#[derive(Parser, Debug)]
#[clap(name = "Benchmark", about = "SMT benchmark", version, rename_all = "kebab-case")]
pub struct BenchmarkCmd {
    /// Size of the tree
    #[clap(short = 's', long = "size")]
    size: usize,
}

fn main() {
    benchmark_smt();
}

/// Run a benchmark for [`Smt`].
pub fn benchmark_smt() {
    let args = BenchmarkCmd::parse();
    let tree_size = args.size;

    // prepare the `leaves` vector for tree creation
    let mut entries = Vec::new();
    for i in 0..tree_size {
        let key = rand_value::<RpoDigest>();
        let value = [ONE, ONE, ONE, Felt::new(i as u64)];
        entries.push((key, value));
    }

    let mut tree = construction(entries.clone(), tree_size).unwrap();
    insertion(&mut tree).unwrap();
    batched_insertion(&mut tree).unwrap();
    batched_update(&mut tree, entries).unwrap();
    proof_generation(&mut tree).unwrap();
}

/// Runs the construction benchmark for [`Smt`], returning the constructed tree.
pub fn construction(entries: Vec<(RpoDigest, Word)>, size: usize) -> Result<Smt, MerkleError> {
    println!("Running a construction benchmark:");
    let now = Instant::now();
    let tree = Smt::with_entries(entries)?;
    let elapsed = now.elapsed();
    println!(
        "Constructed a SMT with {size} key-value pairs in {:.3} seconds",
        elapsed.as_secs_f32(),
    );

    println!("Number of leaf nodes: {}\n", tree.leaves().count());

    Ok(tree)
}

/// Runs the insertion benchmark for the [`Smt`].
pub fn insertion(tree: &mut Smt) -> Result<(), MerkleError> {
    const NUM_INSERTIONS: usize = 1_000;

    println!("Running an insertion benchmark:");

    let size = tree.num_leaves();

    let mut insertion_times = Vec::new();

    for i in 0..NUM_INSERTIONS {
        let test_key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
        let test_value = [ONE, ONE, ONE, Felt::new((size + i) as u64)];

        let now = Instant::now();
        tree.insert(test_key, test_value);
        let elapsed = now.elapsed();
        insertion_times.push(elapsed.as_micros());
    }

    println!(
        "An average insertion time measured by {NUM_INSERTIONS} inserts into an SMT with {size} \
            leaves is {:.3} microseconds\n",
        // calculate the average
        insertion_times.iter().sum::<u128>() as f64 / (NUM_INSERTIONS as f64),
    );

    Ok(())
}

pub fn batched_insertion(tree: &mut Smt) -> Result<(), MerkleError> {
    const NUM_INSERTIONS: usize = 10_000;

    println!("Running a batched insertion benchmark:");

    let size = tree.num_leaves();

    let new_pairs: Vec<(RpoDigest, Word)> = (0..NUM_INSERTIONS)
        .map(|i| {
            let key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
            let value = [ONE, ONE, ONE, Felt::new((size + i) as u64)];
            (key, value)
        })
        .collect();

    let now = Instant::now();
    let mutations = tree.compute_mutations(new_pairs);
    let compute_elapsed = now.elapsed();

    let now = Instant::now();
    tree.apply_mutations(mutations)?;
    let apply_elapsed = now.elapsed();

    println!(
        "An average insert-batch computation time measured by a {NUM_INSERTIONS}-batch into an SMT \
            with {size} leaves over {:.3} milliseconds is {:.3} milliseconds",
        compute_elapsed.as_secs_f64() * 1000.0,
        compute_elapsed.as_secs_f64() * 1000.0 / NUM_INSERTIONS as f64,
    );

    println!(
        "An average insert-batch application time measured by a {NUM_INSERTIONS}-batch into an SMT \
            with {size} leaves over {:.3} milliseconds is {:.3} milliseconds",
        apply_elapsed.as_secs_f64() * 1000.0,
        apply_elapsed.as_secs_f64() * 1000.0 / NUM_INSERTIONS as f64,
    );

    println!(
        "An average batch insertion time measured by a 10k-batch into an SMT with {size} leaves \
            totals to {:.3} milliseconds",
        (compute_elapsed + apply_elapsed).as_secs_f64() * 1000.0,
    );

    println!();

    Ok(())
}

pub fn batched_update(tree: &mut Smt, entries: Vec<(RpoDigest, Word)>) -> Result<(), MerkleError> {
    const NUM_UPDATES: usize = 10_000;
    const REMOVAL_PROBABILITY: f64 = 0.2;

    println!("Running a batched update benchmark:");

    let size = tree.num_leaves();
    let mut rng = thread_rng();

    let new_pairs =
        entries
            .into_iter()
            .choose_multiple(&mut rng, NUM_UPDATES)
            .into_iter()
            .map(|(key, _)| {
                let value = if rng.gen_bool(REMOVAL_PROBABILITY) {
                    EMPTY_WORD
                } else {
                    [ONE, ONE, ONE, Felt::new(rng.gen())]
                };

                (key, value)
            });

    assert_eq!(new_pairs.len(), NUM_UPDATES);

    let now = Instant::now();
    let mutations = tree.compute_mutations(new_pairs);
    let compute_elapsed = now.elapsed();

    let now = Instant::now();
    tree.apply_mutations(mutations)?;
    let apply_elapsed = now.elapsed();

    println!(
        "An average update-batch computation time measured by a {NUM_UPDATES}-batch into an SMT \
            with {size} leaves over {:.3} milliseconds is {:.3} milliseconds",
        compute_elapsed.as_secs_f64() * 1000.0,
        compute_elapsed.as_secs_f64() * 1000.0 / NUM_UPDATES as f64,
    );

    println!(
        "An average update-batch application time measured by a {NUM_UPDATES}-batch into an SMT with \
            {size} leaves over {:.3} milliseconds is {:.3} milliseconds",
        apply_elapsed.as_secs_f64() * 1000.0,
        apply_elapsed.as_secs_f64() * 1000.0 / NUM_UPDATES as f64,
    );

    println!(
        "An average batch update time measured by a 10k-batch into an SMT with {size} leaves \
            totals to {:.3} milliseconds",
        (compute_elapsed + apply_elapsed).as_secs_f64() * 1000.0,
    );

    println!();

    Ok(())
}

/// Runs the proof generation benchmark for the [`Smt`].
pub fn proof_generation(tree: &mut Smt) -> Result<(), MerkleError> {
    const NUM_PROOFS: usize = 20;

    println!("Running a proof generation benchmark:");

    let mut insertion_times = Vec::new();

    let size = tree.num_leaves();

    for i in 0..20 {
        let test_key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
        let test_value = [ONE, ONE, ONE, Felt::new((size + i) as u64)];
        tree.insert(test_key, test_value);

        let now = Instant::now();
        let _proof = tree.open(&test_key);
        insertion_times.push(now.elapsed().as_micros());
    }

    println!(
        "An average proving time measured by {NUM_PROOFS} value proofs in an SMT with {size} \
            leaves in {:.3} microseconds",
        // calculate the average
        insertion_times.iter().sum::<u128>() as f64 / (NUM_PROOFS as f64),
    );

    Ok(())
}
