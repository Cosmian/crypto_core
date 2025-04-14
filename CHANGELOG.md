# Changelog

All notable changes to this project will be documented in this file.

## [10.1.0] - 2025-04-14

### 🚀 Features

- adds a `define_byte_type` macro to easily derive byte types
- always expose the `SymmetricKey` to avoid unnecessary feature activation
- adds shuffling primitives based on a cryptographic RNG

## [10.0.1] - 2025-03-13

### 🐛 Bug Fixes

- Expose missing `generator()` function for the R25519 curve [#87](https://github.com/Cosmian/crypto_core/pull/87)

### 🧪 Testing

- Add context to deserialization error [#86](https://github.com/Cosmian/crypto_core/pull/86)
- Do not unwrap in `test_serialization` [#93](https://github.com/Cosmian/crypto_core/pull/93)

### ⚙️ Miscellaneous Tasks

- Make license BUSL-1.1
- Update cargo deny action [#92](https://github.com/Cosmian/crypto_core/pull/92)

## [10.0.0] - 2024-12-20

### 🚀 Features

- adds implementation of some arithmetic operations for curve points,
- exports a method for raw bytes conversion to R25519PrivateKey
- adds a generic serialization test that can be used by any type implementing Serializable,
- requires the Serializable::Error to implement std::error::Error,
- modifies the Deref implementations for the secrets and keys so that one can access to reference on arrays instead of slices (needed to be compatible with fixed-length byte parsing)

### ⚙️ Miscellaneous Tasks

- Fix cargo-deny allowing license Unicode-3.0

## [9.6.0] - 2024-10-28

### 🚀 Features

- Dereference secrets to &[u8; LENGTH] [#80](https://github.com/Cosmian/crypto_core/pull/80)

### 🐛 Bug Fixes

- Improve `TryFromSlice` error message [#71](https://github.com/Cosmian/crypto_core/pull/71)
- Fix array deserialization [#79](https://github.com/Cosmian/crypto_core/pull/79)

### ⚙️ Miscellaneous Tasks

- Bump curve25519-dalek from 4.1.0 to 4.1.3 for security fix [#78](https://github.com/Cosmian/crypto_core/pull/78)

## [9.5.0] - 2023-07-05

### Features

- derive `Clone` for `SymmetricKey`, `Aes128Gcm` and `Aes256Gcm` structures

## [9.4.0] - 2023-06-10

### Features

- add a `Secret` type to hold sensitive information
- base the `SymmetricKey` type on the Secret type
- add a derive constructor to the `SymmetricKey` that takes a `Secret` seed as
  argument
- add algebraic methods `one` and `zero` to the Curve25519 public key type.

## [9.3.0] - 2023-09-26

### Features

- Add support for RSA key generation, key-wrapping and PKCS#8 import/export

### Fixed

- Fixed export of Curve25519Secret
- Aligned NIST Curves PKC8 import/export with the pkcs8 crate

## [9.2.1] - 2023-09-26

### Features

- Allow the deserializer to perform zero-copy reading (using slices)

## [9.2.0] - 2023-09-11

### Features

- Add support for ECIES over NIST curves: P-192, P-224, P-256, P-384
- Implement encoding traits (pkcs8+der) for NIST curves

## [9.1.0] - 2023-09-01

### Features

- Implement Signature traits (involved in x509-cert crate) for Certificate signing using Ed25519

### Fixed

- use local import of `tinny-keccak` for `kdf!`

### Ci

- Clean hack per run

## [9.0.3] - 2023-08-17

### Bug Fixes

- Reexport Curve 25519 constants
- Reexport `zeroize`
- Reexport `tiny-keccak` for feature `sha3`

## [9.0.2] - 2023-08-13

### Bug Fixes

- make `kdf` public again

## [9.0.1] - 2023-07-13

### Bug Fixes

- Mismatch license in Cargo.toml

## [9.0.0] - 2023-07-11

### Fixed

- Revert RFC 5649 changes on wrap function

## [8.0.0] - 2023-06-13

### Features

- rework of base traits
- get closer to RustCrypto
- added ECIES
- added streaming for ECIES and DEM
- added Ed25519 signature
- libsodium compatibility wherever possible
- symmetric key wrapping RFC-5649 impl
- harden zeroization

## [7.1.0] - 2023-05-02

### Features

- Add ECIES scheme implementation using [Dalek](https://github.com/dalek-cryptography/curve25519-dalek) implementation combined to AES256-GCM

---

## [7.0.0] - 2023-02-17

### Added

### Changed

- use Shake256 from `tiny_keccak` as KDF
- `read_u64()` -> `read_leb128_u64()`
- `write_u64()` -> `write_leb128_u64()`

### Fixed

### Removed

- `#[inline]` directives
- `serde`, `thiserror`, `hex` dependencies
- unused file `entropy.rs`

---

---

## [6.0.0] - 2023-01-10

### Added

### Changed

- Better errors with more information for the user

### Fixed

### Removed

---

---

## [5.0.0] - 2022-11-15

### Added

- `<impl Serializable>::length()`
- `Serializer::with_capacity()`
- `Serializer::write<impl Serializable>()`
- `Deserializer::read<impl Serializable>()`

### Changed

- `<impl Serializable>::try_to_bytes()` now allocates
  `<impl Serializable>::length()` bytes to the `Serializer` on creation
- `kdf!` uses `$crate` local objects => remove `sha3` dependency in caller

### Fixed

### Removed

---

---

## [4.0.1] - 2022-10-24

### Added

### Changed

### Fixed

### Removed

- crate-type `cdylib` in order to help the ios build

---

---

## [4.0.0] - 2022-10-19

### Added

- benches
- `serialization` module
- demo in `examples/demo.rs`

### Changed

- use `Shake128` instead of `Shake256`
- replace `Hc128` by `ChaCha12Rng`
- `README.md` follows template

### Fixed

### Removed

- `Metadata`
- custom `CsRng` interface -> use `RngCore` or `SeedableRng` instead

---

---

## [3.1.0] - 2022-10-06

### Added

- SHAKE256-based KDF
- inline directives

### Changed

### Fixed

### Removed

---

---

## [3.0.0] - 2022-10-04

### Added

- `DhKeyPair` which represents an asymmetric key pair in a space where the
  Computational Diffie-Helman problem is intractable

### Changed

- use constant generics
- use `core` instead of `std` when possible

### Fixed

### Removed

- `NonceTrait::increment()`
- `SymmetricCrypto` trait
- `Block`
- `kdf` module

---

---

## [2.0.0] - 2022-08-22

### Added

- `Eq` super trait to `KeyTrait`
- `from_bytes()` to `SymKey`

### Changed

- Use GenericArrays for keys

### Fixed

### Removed

---

---

## [1.1.1] - 2022-08-19

### Added

### Changed

### Fixed

- Fix `cargo audit`: upgrade bindgen crate version to 0.60

### Removed

---

---

## [1.1.0] - 2022-08-16

### Added

- Add `SymKey` trait to add `as_byte()` method
- add `Zeroize` as `KeyTrait` super trait

### Changed

- Pass output length as a constant generic to the HKDF

### Fixed

- typos in doc

### Removed

---

---

## [1.0.1] - 2022-08-02

### Added

- Add `PartialEq + Eq` as `KeyTrait` super trait
- Derive `Hash` for `SymmetricCrypto::Key` and
  `AsymmetricCrypto::X25519PrivateKey`

### Changed

### Fixed

### Removed

---

---

## [1.0.0] - 2022-07-19

### Added

- All code from `crypto_base` v2.1.0 used by `cover_crypt`

### Changed

### Fixed

### Removed

---
