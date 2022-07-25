# cosmian_crypto_core &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]


[Build Status]: https://img.shields.io/github/workflow/status/Cosmian/crypto_core/CI%20checks/main
[actions]: https://github.com/Cosmian/crypto_core/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/cosmian_crypto_core.svg
[crates.io]: https://crates.io/crates/cosmian_crypto_core

This crate implements crypto primitives which are used in many other
Cosmian cryptographic resources:

- symmetric cryptography primitives can be found in the `symmetric_crypto` module;
- asymmetric cryptography primitives can be found in the `asymmetric_crypto` module;
- a Key Derivation Function (KDF) can be found in the `kdf` module;
- a Random Number Generator (RNG) can be found in the `entropy` module.

We also define `CryptoCoreError`, our error type, and a few traits.

## Symmetric Crypto

We implement a Data Encapsulation Mechanism (DEM) based on the AES 256 GCM
algorithm, as described in the [ISO 2004](https://www.shoup.net/iso/std6.pdf).
This implementation is 128-bits secure.

We use the [`aes_gcm`](https://docs.rs/aes-gcm/latest/aes_gcm/index.html)
implementation of the AES GCM algorithm. This implementation make use of the
AES instruction when available, which allows a high encryption speed.

## Asymmetric Crypto

We implement a public and a private key objects based on Curve25519. This is
the fastest elliptic curve known when implementing these objects. Its security
level is also 128 bits.

We use the [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
implementation, which also offers an implementation of the Ristretto technique
to construct a prime order group on the curve. We use this group to implement
our public key.

## Key Derivation Function (KDF)

We use the [`hkdf`](https://docs.rs/hkdf/latest/hkdf/) implementation of the
HKDF algorithm, along with the Sha256 implementation of the Rust standard
library in order to implement our KDF.

Since Sha256 is 128-bits secure, this makes our KDF 128-bits secure too.

## Random Number Generator (RNG)

We use the implementation of the HC128 algorithm from the
[Rust standard library](https://docs.rs/rand/0.5.0/rand/prng/hc128/struct.Hc128Rng.html)
to construct our RNG. It is therefore 128-bits secure.

## Building

The default feature schemes can all be built to a WASM target.
