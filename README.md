# Cosmian CryptoCore &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]


[Build Status]: https://img.shields.io/github/workflow/status/Cosmian/crypto_core/CI%20checks/main
[actions]: https://github.com/Cosmian/crypto_core/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/cosmian_crypto_core.svg
[crates.io]: https://crates.io/crates/cosmian_crypto_core

This crate implements the cryptographic primitives which are used in many other
Cosmian resources:

- a Data Encryption Method (DEM) based on AES256-GCM (128 bytes of security)
  offering a simple API (Nonce management and authentication checks are internals);
- a Diffie-Hellman key pair based on the curve25519 (128 bytes of security)
  allowing implementation of Diffie-Hellman based asymmetric cryptography;
- a Random Number Generator (RNG) implementing the ChaCha algorithm with 12
  rounds (128 bytes of security).
- a Key Derivation Function (KDF) based on SHAKE128 (128 bytes of security);

All these primitives are use pure rust implementations, are secure, and used
the fastest known algorithms. They offer a great basis on which to build more
complex softwares.

## Getting started

### Build

To install and build Cosmian CryptoCore, just clone the repo:
```
git clone https://github.com/Cosmian/crypto_core.git
```
and build it with Cargo:
```
cargo build --release
```

### Use

To use Cosmian CryptoCore in another Rust software, just add the dependency
using Cargo:
```
cargo add cosmian_crypto_core
```
and use it in your project!

### Run tests and benchmarks

Tests can be run with:
```
cargo test --release
```

Benchmarks can be run with:
```
cargo bench
```

## Features

The benchmarks given below are run on a Intel(R) Core(TM) i7-10750H CPU @ 3.20GHz.

### Asymmetric Crypto

This crate implements a Diffie-Hellman asymmetric key pair based on the
Curve25519. This is one of the fastest elliptic curves known at this time and
it offers 128 bits of security.

It uses the [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
implementation, which offers an implementation of the Ristretto technique to
construct a prime order group on the curve. This group is used to implement
the public key.

```
Bench the Group-Scalar multiplication on which is based the Diffie-Helman key exchange
                        time:   [59.932 µs 60.131 µs 60.364 µs]
```

### Symmetric Crypto

This crate implements a Data Encryption Method (DEM) based on the AES256-GCM
algorithm, as described in the [ISO 2004](https://www.shoup.net/iso/std6.pdf).
This implementation is 128-bits secure in both the classic and the post-quantum
models.

It uses the [`aes_gcm`](https://docs.rs/aes-gcm/latest/aes_gcm/index.html)
implementation of the AES GCM algorithm. This implementation makes use of the
AES instruction set when available, which allows for a high encryption speed.

```
Bench the DEM encryption of a 2048-bytes message without additional data
                        time:   [2.7910 µs 2.7911 µs 2.7914 µs]

Bench the DEM decryption of a 2048-bytes message without additional data
                        time:   [2.7074 µs 2.7079 µs 2.7085 µs]
```

### Random Number Generator (RNG)

This crate uses the implementation of the CHACHA algorithm with 12 rounds from
the [`rand_chacha`](https://rust-random.github.io/rand/rand_chacha/index.html)
crate to construct our RNG. It is therefore 128-bits secure.

```
Bench the generation of a cryptographic RNG
                        time:   [1.2355 µs 1.2368 µs 1.2382 µs]
```

### Key Derivation Function (KDF)

This crate uses the pure rust implementation of the SHAKE128 algorithm from the
[sha3](https://docs.rs/sha3/latest/sha3) crate. This allows implementing a KDF
which 128-bits secure for input sizes of at least 256 bits (32 bytes).

```
bench the KDF derivation of a 32-bytes IKM into a 64-bytes key
                        time:   [1.1065 µs 1.1067 µs 1.1070 µs]
```

## Documentation

The documentation can be generated using Cargo:
```
cargo docs
```

It is also available on
[doc.rs](https://docs.rs/cosmian_crypto_core/latest/cosmian_crypto_core/).
