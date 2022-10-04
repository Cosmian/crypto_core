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
pub mod symmetric_crypto;

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::error::CryptoCoreError;

pub mod reexport {
    // reexport `rand_core` so that the PRNGs implement the correct version of
    // the traits
    pub use rand_core;
}

/// Cryptographic key.
pub trait KeyTrait<const LENGTH: usize>:
    Clone + Eq + PartialEq + Send + Sized + Sync + Zeroize + ZeroizeOnDrop
{
    /// Key length
    const LENGTH: usize = LENGTH;

    /// Generates a new random key.
    #[must_use]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self;

    /// Converts the given key into a vector of bytes.
    #[must_use]
    fn to_bytes(&self) -> [u8; LENGTH];

    /// Tries to convert the given bytes into a key.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError>;
}
