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

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::error::CryptoCoreError;

pub mod reexport {
    // reexport `rand_core` so that the PRNG implement the correct version of the traits
    pub use rand_core;
}

/// Trait defining a cryptographic key.
pub trait KeyTrait<const LENGTH: usize>:
    PartialEq + Eq + Send + Sync + Sized + Clone + Zeroize + ZeroizeOnDrop
{
    /// Key length
    const LENGTH: usize = LENGTH;

    /// Generate a new random key.
    #[must_use]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self;

    /// Convert the given key into a vector of bytes.
    #[must_use]
    fn to_bytes(&self) -> [u8; LENGTH];

    /// Convert the given bytes into a key. An error is returned in case the
    /// conversion fails.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError>;
}
