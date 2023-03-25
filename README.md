# Miden Crypto
This crate contains cryptographic primitives used in Polygon Miden.

## Hash
[Hash module](./src/hash) provides a set of cryptographic hash functions which are used by the Miden VM and the Miden rollup. Currently, these functions are:

* [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash function with 256-bit, 192-bit, or 160-bit output. The 192-bit and 160-bit outputs are obtained by truncating the 256-bit output of the standard BLAKE3.
* [RPO](https://eprint.iacr.org/2022/1577) hash function with 256-bit output. This hash function is an algebraic hash function suitable for recursive STARKs.

For performance benchmarks of these hash functions and their comparison to other popular hash functions please see [here](./benches/).

## Merkle
[Merkle module](./src/merkle/) provides a set of data structures related to Merkle trees. All these data structures are implemented using the RPO hash function described above. The data structures are:

* `MerkleTree`: a regular fully-balanced binary Merkle tree. The depth of this tree can be at most 64.
* `SimpleSmt`: a Sparse Merkle Tree, mapping 63-bit keys to 4-element leaf values.
* `MerklePathSet`: a collection of Merkle authentication paths all resolving to the same root. The length of the paths can be at most 64.
* `MerkleStore`: a collection of Merkle trees of different heights designed to efficiently store trees with common subtrees.
* `Mmr`: a Merkle mountain range structure designed to function as an append-only log.

The module also contains additional supporting components such as `NodeIndex`, `MerklePath`,  and `MerkleError`  to assist with tree indexation, opening proofs, and reporting inconsistent arguments/state.

## Extra
[Root module](./src/lib.rs) provides a set of constants, types, aliases, and utils required to use the primitives of this library.

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.

Both of these features imply the use of [alloc](https://doc.rust-lang.org/alloc/) to support heap-allocated collections.

To compile with `no_std`, disable default features via `--no-default-features` flag.

## Testing

You can use cargo defaults to test the library:

```shell
cargo test
```

However, some of the functions are heavy and might take a while for the tests to complete. In order to test in release mode, we have to replicate the test conditions of the development mode so all debug assertions can be verified.

We do that by enabling some special [flags](https://doc.rust-lang.org/cargo/reference/profiles.html) for the compilation.

```shell
RUSTFLAGS="-C debug-assertions -C overflow-checks -C debuginfo=2" cargo test --release
```

## License
This project is [MIT licensed](./LICENSE).
