//! This crate implements crypto primitives which are used in many other
//! Cosmian cryptographic resources.

mod error;

pub mod asymmetric_crypto;
pub mod bytes_ser_de;
pub mod kdf;
pub mod reexport {
    // reexport `rand_core` so that the PRNGs implement the correct version of
    // the traits
    pub use rand_chacha::rand_core;
}
pub mod symmetric_crypto;

use reexport::rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::error::CryptoCoreError;

/// Use ChaCha with 12 rounds as cryptographic RNG.
pub type CsRng = rand_chacha::ChaCha12Rng;

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
