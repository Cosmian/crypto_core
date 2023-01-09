# Changelog

All notable changes to this project will be documented in this file.

---

## Unreleased

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

- `DhKeyPair` which represents an asymmetric key pair in a space wher the
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
