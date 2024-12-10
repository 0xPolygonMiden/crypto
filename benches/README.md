# Miden VM Hash Functions
In the Miden VM, we make use of different hash functions. Some of these are "traditional" hash functions, like `BLAKE3`, which are optimized for out-of-STARK performance, while others are algebraic hash functions, like `Rescue Prime`, and are more optimized for a better performance inside the STARK. In what follows, we benchmark several such hash functions and compare against other constructions that are used by other proving systems. More precisely, we benchmark:

* **BLAKE3** as specified [here](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) and implemented [here](https://github.com/BLAKE3-team/BLAKE3) (with a wrapper exposed via this crate).
* **SHA3** as specified [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and implemented [here](https://github.com/novifinancial/winterfell/blob/46dce1adf0/crypto/src/hash/sha/mod.rs).
* **Poseidon** as specified [here](https://eprint.iacr.org/2019/458.pdf) and implemented [here](https://github.com/mir-protocol/plonky2/blob/806b88d7d6e69a30dc0b4775f7ba275c45e8b63b/plonky2/src/hash/poseidon_goldilocks.rs) (but in pure Rust, without vectorized instructions).
* **Rescue Prime (RP)** as specified [here](https://eprint.iacr.org/2020/1143) and implemented [here](https://github.com/novifinancial/winterfell/blob/46dce1adf0/crypto/src/hash/rescue/rp64_256/mod.rs).
* **Rescue Prime Optimized (RPO)** as specified [here](https://eprint.iacr.org/2022/1577) and implemented in this crate.
* **Rescue Prime Extended (RPX)** a variant of the [xHash](https://eprint.iacr.org/2023/1045) hash function as implemented in this crate.

## Comparison and Instructions

### Comparison
We benchmark the above hash functions using two scenarios. The first is a 2-to-1 $(a,b)\mapsto h(a,b)$ hashing where both $a$, $b$ and $h(a,b)$ are the digests corresponding to each of the hash functions.
The second scenario is that of sequential hashing where we take a sequence of length $100$ field elements and hash these to produce a single digest. The digests are $4$ field elements in a prime field with modulus $2^{64} - 2^{32} + 1$ (i.e., 32 bytes) for Poseidon, Rescue Prime and RPO, and an array `[u8; 32]` for SHA3 and BLAKE3.

#### Scenario 1: 2-to-1 hashing `h(a,b)`

| Function            | BLAKE3 | SHA3    | Poseidon  | Rp64_256  | RPO_256 | RPX_256 |
| ------------------- | ------ | ------- | --------- | --------- | ------- | ------- |
| Apple M1 Pro        | 76 ns  | 245 ns  |  1.5 µs   |  9.1 µs   | 5.2 µs  | 2.7 µs  |
| Apple M2 Max        | 71 ns  | 233 ns  |  1.3 µs   |  7.9 µs   | 4.6 µs  | 2.4 µs  |
| Amazon Graviton 3   | 108 ns |         |           |           | 5.3 µs  | 3.1 µs  |
| AMD Ryzen 9 5950X   | 64 ns  | 273 ns  |  1.2 µs   |  9.1 µs   | 5.5 µs  |         |
| AMD EPYC 9R14       | 83 ns  |         |           |           | 4.3 µs  | 2.4 µs  |
| Intel Core i5-8279U | 68 ns  | 536 ns  |  2.0 µs   |  13.6 µs  | 8.5 µs  | 4.4 µs  |
| Intel Xeon 8375C    | 67 ns  |         |           |           | 8.2 µs  |         |

#### Scenario 2: Sequential hashing of 100 elements `h([a_0,...,a_99])`

| Function            | BLAKE3 | SHA3    | Poseidon  | Rp64_256  | RPO_256 | RPX_256 |
| ------------------- | -------| ------- | --------- | --------- | ------- | ------- |
| Apple M1 Pro        | 1.0 µs | 1.5 µs  |  19.4 µs  |   118 µs  | 69 µs   | 35 µs   |
| Apple M2 Max        | 0.9 µs | 1.5 µs  |  17.4 µs  |   103 µs  | 60 µs   | 31 µs   |
| Amazon Graviton 3   | 1.4 µs |         |           |           | 69 µs   | 41 µs   |
| AMD Ryzen 9 5950X   | 0.8 µs | 1.7 µs  |  15.7 µs  |   120 µs  | 72 µs   |         |
| AMD EPYC 9R14       | 0.9 µs |         |           |           | 56 µs   | 32 µs   |
| Intel Core i5-8279U | 0.9 µs |         |           |           | 107 µs  | 56 µs   |
| Intel Xeon 8375C    | 0.8 µs |         |           |           | 110 µs  |         |

Notes:
- On Graviton 3, RPO256 and RPX256 are run with SVE acceleration enabled.
- On AMD EPYC 9R14, RPO256 and RPX256 are run with AVX2 acceleration enabled.

### Instructions
Before you can run the benchmarks, you'll need to make sure you have Rust [installed](https://www.rust-lang.org/tools/install). After that, to run the benchmarks for RPO and BLAKE3, clone the current repository, and from the root directory of the repo run the following:

 ```
 cargo bench hash
 ```

To run the benchmarks for Rescue Prime, Poseidon and SHA3, clone the following [repository](https://github.com/Dominik1999/winterfell.git) as above, then checkout the `hash-functions-benches` branch, and from the root directory of the repo run the following:

```
cargo bench hash
```

# Miden VM DSA

We make use of the following digital signature algorithms (DSA) in the Miden VM:

* **RPO-Falcon512** as specified [here](https://falcon-sign.info/falcon.pdf) with the one difference being the use of the RPO hash function for the hash-to-point algorithm (Algorithm 3 in the previous reference) instead of SHAKE256.
* **RPO-STARK** as specified [here](https://eprint.iacr.org/2024/1553), where the parameters are the ones for the unique-decoding regime (UDR) with the two differences:
  *  We rely on the conjecture on the security of the toy protocol in the [ethSTARK](https://eprint.iacr.org/2021/582) paper.
  *  The number of FRI queries is $30$ and the grinding factor is $12$ bits. Thus using the previous point we can argue that the modified version achieves at least $102$ bits of average-case existential unforgeability security against $2^{113}$-query bound adversaries that can obtain up to $2^{64}$ signatures under the same public key.



## Comparison and Instructions

### Comparison


#### Key Generation

##### Public Key

| Function            | Falcon512 | RPO-STARK |
| ------------------- | --------- | --------- |
| Apple M1 Pro        |           |           |
| Apple M2 Max        |           |           |
| Amazon Graviton 3   |           |
| AMD Ryzen 9 5950X   |           |           |
| AMD EPYC 9R14       |           |           |
| Intel Core i5-8279U |  594 µs   |   9 µs    |
| Intel Xeon 8375C    |           |           |

##### Secret Key

| Function            | Falcon512 | RPO-STARK |
| ------------------- | --------- | --------- |
| Apple M1 Pro        |           |           |
| Apple M2 Max        |           |           |
| Amazon Graviton 3   |           |
| AMD Ryzen 9 5950X   |           |           |
| AMD EPYC 9R14       |           |           |
| Intel Core i5-8279U |  584 ms   |  865 ns   |
| Intel Xeon 8375C    |           |           |

#### Signature Generation

| Function            | Falcon512 | RPO-STARK |
| ------------------- | --------- | --------- |
| Apple M1 Pro        |           |           |
| Apple M2 Max        |           |           |
| Amazon Graviton 3   |           |
| AMD Ryzen 9 5950X   |           |           |
| AMD EPYC 9R14       |           |           |
| Intel Core i5-8279U |  1.8 ms   |  130 ms   |
| Intel Xeon 8375C    |           |           |

#### Signature Verification

| Function            | Falcon512 | RPO-STARK |
| ------------------- | --------- | --------- |
| Apple M1 Pro        |           |           |
| Apple M2 Max        |           |           |
| Amazon Graviton 3   |           |
| AMD Ryzen 9 5950X   |           |           |
| AMD EPYC 9R14       |           |           |
| Intel Core i5-8279U |  1.2 ms   |  7.9 ms   |
| Intel Xeon 8375C    |           |           |

### Instructions
Before you can run the benchmarks, you'll need to make sure you have Rust [installed](https://www.rust-lang.org/tools/install). After that, to run the benchmarks, clone the current repository, and from the root directory of the repo run the following:

 ```
 cargo bench --bench dsa
 ```