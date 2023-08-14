use clap::Parser;
use miden_crypto::{
    hash::rpo::RpoDigest,
    merkle::MerkleError,
    Felt, Word, ONE,
    {hash::rpo::Rpo256, merkle::TieredSmt},
};
use rand_utils::rand_value;
use std::time::Instant;

#[derive(Parser, Debug)]
#[clap(
    name = "Benchmark",
    about = "Tiered SMT benchmark",
    version,
    rename_all = "kebab-case"
)]
pub struct BenchmarkCmd {
    /// Size of the tree
    #[clap(short = 's', long = "size")]
    size: u64,

    /// Run the construction benchmark
    #[clap(short = 'c', long = "construction")]
    construction: bool,

    /// Run the insertion benchmark
    #[clap(short = 'i', long = "insertion")]
    insertion: bool,

    /// Run the proof generation benchmark
    #[clap(short = 'p', long = "proof-generation")]
    proof_generation: bool,
}

fn main() {
    benchmark_tsmt();
}

/// Run a benchmark for the Tiered SMT.
pub fn benchmark_tsmt() {
    let args = BenchmarkCmd::parse();
    let tree_size = args.size;

    // prepare the `leaves` vector for tree creation
    let mut leaves = Vec::new();
    for i in 0..tree_size {
        let key = rand_value::<RpoDigest>();
        let value = [ONE, ONE, ONE, Felt::new(i)];
        leaves.push((key, value));
    }

    let mut tree: Option<TieredSmt> = None;

    // if the `-c` argument was specified
    if args.construction {
        tree = Some(construction(leaves.clone(), tree_size).unwrap());
    }

    // if the `-i` argument was specified
    if args.insertion {
        if let Some(inner_tree) = tree {
            tree = Some(insertion(inner_tree, tree_size).unwrap());
        } else {
            let inner_tree = TieredSmt::with_leaves(leaves.clone()).unwrap();
            tree = Some(insertion(inner_tree, tree_size).unwrap());
        }
    }

    // if the `-p` argument was specified
    if args.proof_generation {
        if let Some(inner_tree) = tree {
            proof_generation(inner_tree, tree_size).unwrap();
        } else {
            let inner_tree = TieredSmt::with_leaves(leaves).unwrap();
            proof_generation(inner_tree, tree_size).unwrap();
        }
    }
}

/// Run the construction benchmark for the Tiered SMT.
pub fn construction(leaves: Vec<(RpoDigest, Word)>, size: u64) -> Result<TieredSmt, MerkleError> {
    println!("Running a construction benchmark:");
    let now = Instant::now();
    let tree = TieredSmt::with_leaves(leaves)?;
    let elapsed = now.elapsed();
    println!(
        "Constructed a TSMT with {} key-value pairs in {:.3} seconds",
        size,
        elapsed.as_secs_f32(),
    );

    // Count how many nodes end up at each tier
    let mut nodes_num_16_32_48 = (0, 0, 0);

    tree.upper_leaf_nodes().for_each(|(index, _)| match index.depth() {
        16 => nodes_num_16_32_48.0 += 1,
        32 => nodes_num_16_32_48.1 += 1,
        48 => nodes_num_16_32_48.2 += 1,
        _ => unreachable!(),
    });

    println!("Number of nodes on depth 16: {}", nodes_num_16_32_48.0);
    println!("Number of nodes on depth 32: {}", nodes_num_16_32_48.1);
    println!("Number of nodes on depth 48: {}", nodes_num_16_32_48.2);
    println!("Number of nodes on depth 64: {}\n", tree.bottom_leaves().count());

    Ok(tree)
}

/// Run the insertion benchmark for the Tiered SMT.
pub fn insertion(mut tree: TieredSmt, size: u64) -> Result<TieredSmt, MerkleError> {
    println!("Running an insertion benchmark:");

    let mut insertion_times = Vec::new();

    for i in 0..20 {
        let test_key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
        let test_value = [ONE, ONE, ONE, Felt::new(size + i)];

        let now = Instant::now();
        tree.insert(test_key, test_value);
        let elapsed = now.elapsed();
        insertion_times.push(elapsed.as_secs_f32());
    }

    println!(
        "An average insertion time measured by 20 inserts into a TSMT with {} key-value pairs is {:.3} milliseconds\n",
        size,
        // calculate the average by dividing by 20 and convert to milliseconds by multiplying by 
        // 1000. As a result, we can only multiply by 50
        insertion_times.iter().sum::<f32>() * 50f32,
    );

    Ok(tree)
}

/// Run the proof generation benchmark for the Tiered SMT.
pub fn proof_generation(mut tree: TieredSmt, size: u64) -> Result<(), MerkleError> {
    println!("Running a proof generation benchmark:");

    let mut insertion_times = Vec::new();

    for i in 0..20 {
        let test_key = Rpo256::hash(&rand_value::<u64>().to_be_bytes());
        let test_value = [ONE, ONE, ONE, Felt::new(size + i)];
        tree.insert(test_key, test_value);

        let now = Instant::now();
        let _proof = tree.prove(test_key);
        let elapsed = now.elapsed();
        insertion_times.push(elapsed.as_secs_f32());
    }

    println!(
        "An average proving time measured by 20 value proofs in a TSMT with {} key-value pairs in {:.3} microseconds",
        size,
        // calculate the average by dividing by 20 and convert to microseconds by multiplying by
        // 1000000. As a result, we can only multiply by 50000
        insertion_times.iter().sum::<f32>() * 50000f32,
    );

    Ok(())
}
