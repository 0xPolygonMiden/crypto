# Miden Crypto
This crate contains cryptographic primitives used in Polygon Miden.

## Hash
[Hash module](./src/hash) provides a set of cryptographic hash functions which are used by Miden VM and Miden Rollup. Currently, these functions are:

* [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash function with 256-bit, 192-bit, or 160-bit output. The 192-bit and 160-bit outputs are obtained by truncating the 256-bit output of the standard BLAKE3.
* [RPO](https://eprint.iacr.org/2022/1577) hash function with 256-bit output. This hash function is an algebraic hash function suitable for recursive STARKs.

## Merkle
[Merkle module](./src/merkle/) provides a set of data structures related to Merkle tree. All these data structures are implemented using RPO hash function described above. The data structure are:

* `MerkleTree`: a regular fully-balanced binary Merkle tree. The depth of this tree can be at most 64.
* `MerklePathSet`: a collection of Merkle authentication paths all resolving to the same root. The length of the paths can be at most 64.

## Crate features
This carate can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.

Both of these features imply use of [alloc](https://doc.rust-lang.org/alloc/) to support heap-allocated collections.

To compile with `no_std`, disable default features via `--no-default-features` flag.

## License
This project is [MIT licensed](./LICENSE).
