//! This crate implements crypto primitives which are used in many other
//! Cosmian cryptographic resources:
//!
//! - symmetric cryptography primitives can be found in the `symmetric_crypto` module;
//! - asymmetric cryptography primitives can be found in the `asymmetric_crypto` module;
//! - a Key Derivation Function (KDF) can be found in the `kdf` module;
//! - a Random Number Generator (RNG) can be found in the `entropy` module.
//!
//! `CryptoCoreError` is the error type of the library.
//!
//! This crate also exposes a few traits for cryptographic objects defined in
//! the modules.

mod error;

pub mod asymmetric_crypto;
pub mod entropy;
pub mod kdf;
pub mod symmetric_crypto;

pub use crate::error::CryptoCoreError;

/// Trait defining a cryptographic key.
pub trait KeyTrait: PartialEq + Eq + Send + Sync + Sized + Clone {
    /// Number of bytes in the serialized key.
    const LENGTH: usize;

    /// Convert the given key into a vector of bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Convert the given bytes into a key. An error is returned in case the
    /// conversion fails.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError>;
}
