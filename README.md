# cosmian_crypto_core &emsp; [![Build Status]][actions] [![Latest Version]][crates.io]


[Build Status]: https://img.shields.io/github/workflow/status/Cosmian/crypto_core/CI%20checks/main
[actions]: https://github.com/Cosmian/crypto_core/actions?query=branch%3Amain
[Latest Version]: https://img.shields.io/crates/v/cosmian_crypto_core.svg
[crates.io]: https://crates.io/crates/cosmian_crypto_core

This crate implements crypto primitives which are used in many other
Cosmian cryptographic resources:

- symmetric cryptography primitives can be found in the `symmetric_crypto` module;
- asymmetric cryptography primitives can be found in the `asymmetric_crypto` module;
- a Random Number Generator (RNG) can be found in the `entropy` module.

The crate also defines `CryptoCoreError`, the error type, and a few traits.

## Symmetric Crypto

This crate implements a Data Encapsulation Mechanism (DEM) based on the AES 256
GCM algorithm, as described in the [ISO 2004](https://www.shoup.net/iso/std6.pdf).
This implementation is 128-bits secure.

It uses the [`aes_gcm`](https://docs.rs/aes-gcm/latest/aes_gcm/index.html)
implementation of the AES GCM algorithm. This implementation makes use of the
AES instruction set when available, which allows for a high encryption speed.

## Asymmetric Crypto

This crate implements a public and a private key objects based on Curve25519.
This one of the fastest elliptic curves known when implementing these objects.
Its security level is also 128 bits.

It uses the [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
implementation, which offers an implementation of the Ristretto technique to
construct a prime order group on the curve. This group is used to implement
the public key.

## Random Number Generator (RNG)

This crate uses the implementation of the CHACHA algorithm with 12 rounds from
the [`rand_chacha`](https://rust-random.github.io/rand/rand_chacha/index.html)
crate to construct our RNG. It is therefore 128-bits secure.

## Building

The default feature schemes can all be built to a WASM target.
