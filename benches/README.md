# Miden VM Hash Functions 
In the Miden VM, we make use of different hash functions. Some of these are "traditional" hash functions, like `BLAKE3`, which are optimized for out-of-STARK performance, while others are algebraic hash functions, like `Rescue Prime`, and are more optimized for a better performance inside the STARK. In what follows, we benchmark several such hash functions and compare against other constructions that are used by other proving systems. More precisely, we benchmark:

* **Rescue Prime:**
As specified [here](https://eprint.iacr.org/2020/1143) and implemented [here](https://github.com/novifinancial/winterfell/blob/46dce1adf0/crypto/src/hash/rescue/rp64_256/mod.rs).

* **Rescue Prime Optimized:**
As specified [here](https://eprint.iacr.org/2022/1577) and implemented in this crate.

* **BLAKE3:**
As specified [here](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) and implemented in this crate.

* **SHA3:**
As specified [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and implemented [here](https://github.com/novifinancial/winterfell/blob/46dce1adf0/crypto/src/hash/sha/mod.rs).

* **Poseidon:**
As specified [here](https://eprint.iacr.org/2019/458.pdf) and implemented (in pure Rust, without vectorized instructions) [here](https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/hash/poseidon_goldilocks.rs).

## Comparison and Instructions

### Comparison
We benchmark the above hash functions using two scenarios. The first is a 2-to-1 $(a,b)\mapsto h(a,b)$ hashing where both $a$, $b$ and $h(a,b)$ are the digests corresponding to each of the hash functions.
The second scenario is that of sequential hashing where we take a sequence of length $100$ field elements and hash these to produce a single digest. The digests are $4$ field elements (i.e. 256-bit) for Poseidon, Rescue Prime and RPO, and an array `[u8;32]` for SHA3 and BLAKE3.

#### Scenario 1: 2-to-1 hashing `h(a,b)` 

| Function          | BLAKE3 | SHA3    | Poseidon  | Rp64_256  | RPO_256 |
| ----------------- | ------ | --------| --------- | --------- | ------- |
| Apple M1 Pro      | 80 ns  | 245 ns  |  1.3 us   |  9.1 us   | 5.4 us  |
| Apple M2          | 76 ns  | 233 ns  |  1.2 us   |  7.9 us   | 5.0 us  |
| AMD Ryzen 9 5950X | 64 ns  | 273 ns  |  1.2 us   |  9.1 us   | 5.5 us  |

#### Scenario 2: Sequential hashing of 100 elements `h([a_0,...,a_99])`

| Function          | BLAKE3 | SHA3    | Poseidon  | Rp64_256  | RPO_256 |
| ----------------- | -------| ------- | --------- | --------- | ------- |
| Apple M1 Pro      | 1.1 us | 1.5 us  |  17.3 us  |   118 us  | 70 us   |
| Apple M2          | 1.0 us  | 1.5 us  |  15.5 us  |   103 us  | 65 us   |
| AMD Ryzen 9 5950X | 0.8 us | 1.7 us  |  15.7 us  |   120 us  | 72 us   |

### Instructions
Before you can run the benchmarks, you'll need to make sure you have Rust [installed](https://www.rust-lang.org/tools/install). After that, to run the benchmarks for RPO and BLAKE3, clone the current repository, and from the root directory of the repo run the following:

 ```
 cargo bench --bench hash
 ```

To run the benchmarks for Rescue Prime, Poseidon and SHA3, clone the following [repository](https://github.com/Dominik1999/winterfell.git) as above, then checkout the `hash-functions-benches` branch, and from the root directory of the repo run the following:

```
cargo bench --bench hash
```