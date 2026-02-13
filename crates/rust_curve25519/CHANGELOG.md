# Changelog

All notable changes to this crate will be documented in this file.

## [1.0.0] - 2026-02-13

### 🚀 Features

- Initial pure-Rust Curve25519 (Ristretto25519) provider implementing the `R25519GroupProvider` marker trait.
- Expose `R25519Point` and `R25519Scalar` building blocks and validate compatibility with the generic KEM adapter.

### 🧪 Testing

- Add cyclic-group/NIKE/KEM conformance tests using the core trait test helpers.

### ⚙️ Miscellaneous Tasks

- Add this crate changelog.
