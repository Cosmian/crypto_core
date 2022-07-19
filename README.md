# cosmian_crypto_base_anssi &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]


[Build Status]: https://img.shields.io/github/workflow/status/Cosmian/crypto_base/CI%20checks/main
[actions]: https://github.com/Cosmian/crypto_base/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/cosmian_crypto_base.svg
[crates.io]: https://crates.io/crates/cosmian_crypto_base

This crate implements crypto primitives which are used in many other Cosmian crypto resources

- symmetric crypto: AES 256 GCM
- elliptic curves: Ristretto Curve 25519
- KDF: HKDF 256
- entropy: Cryptographically secure pseudo random generators

It also exposes a few traits, `SymmetricCrypto` and `AsymmetricCrypto` (aka Public Key Crypto), `DEM`,... which are used as building blocks for other constructions.


## Building

The default feature schemes can all be built to a WASM target.

### Benchmarks

Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz - 6400 bogomips . Single Threaded.

```
Bench of leaves generation from a node with varying depth (2500 rounds per depth)
Average: 76 nano per leave for depth: 4 (16 leaves)
Average: 79 nano per leave for depth: 5 (32 leaves)
Average: 79 nano per leave for depth: 6 (64 leaves)
Average: 81 nano per leave for depth: 7 (128 leaves)
Average: 80 nano per leave for depth: 8 (256 leaves)
Average: 79 nano per leave for depth: 9 (512 leaves)
Average: 78 nano per leave for depth: 10 (1024 leaves)
Average: 78 nano per leave for depth: 11 (2048 leaves)
Average: 77 nano per leave for depth: 12 (4096 leaves)
Average: 77 nano per leave for depth: 13 (8192 leaves)
Average: 76 nano per leave for depth: 14 (16384 leaves)
Average: 77 nano per leave for depth: 15 (32768 leaves)
Average: 77 nano per leave for depth: 16 (65536 leaves)
```

```
Bench of a trapdoor serialization/de-serialization averaged over 50000 rounds
   - 1 nodes: serialization/de-serialization 49/38 nanos)
   - 2 nodes: serialization/de-serialization 54/39 nanos)
   - 3 nodes: serialization/de-serialization 55/40 nanos)
   - 4 nodes: serialization/de-serialization 69/49 nanos)
   - 5 nodes: serialization/de-serialization 69/47 nanos)
   - 6 nodes: serialization/de-serialization 73/49 nanos)
   - 7 nodes: serialization/de-serialization 68/47 nanos)
   - 8 nodes: serialization/de-serialization 73/50 nanos)
   - 9 nodes: serialization/de-serialization 83/55 nanos)
   - 10 nodes: serialization/de-serialization 82/56 nanos)
```
