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
* `MerklePathSet`: a collection of Merkle authentication paths all resolving to the same root. The length of the paths can be at most 64.

## Crate features
This crate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.

Both of these features imply the use of [alloc](https://doc.rust-lang.org/alloc/) to support heap-allocated collections.

To compile with `no_std`, disable default features via `--no-default-features` flag.

## License
This project is [MIT licensed](./LICENSE).
