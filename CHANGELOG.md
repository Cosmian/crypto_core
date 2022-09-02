# Changelog

All notable changes to this project will be documented in this file.

---
## [2.0.1] - 2022-09-02
### Added
- `Hash` super trait to `SymKey`
### Changed
### Fixed
### Removed
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
