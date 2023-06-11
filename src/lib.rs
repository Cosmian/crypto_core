//! This crate implements crypto primitives which are used in many other
//! Cosmian cryptographic resources.

mod asymmetric_crypto;
mod blake2;
pub mod bytes_ser_de;
mod ecies;
mod error;
mod kdf;
pub mod reexport {
    // reexport `rand_core` so that the PRNGs implement the correct version of
    // the traits
    pub use rand_chacha::rand_core;
    // reexport the signature Traits
    pub use signature;
    // reexport the aead traits
    pub use aead;
}
pub mod symmetric_crypto;

pub use crate::error::CryptoCoreError;
pub use ::blake2::*;
pub use asymmetric_crypto::*;
pub use ecies::*;

use reexport::rand_core::CryptoRngCore;
use std::hash::Hash;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Use `ChaCha` with 12 rounds as cryptographic RNG.
pub type CsRng = rand_chacha::ChaCha12Rng;

/// Cryptographic bytes
///
/// The bytes should be thread-safe and comparable.
/// The bytes are NOT clonable by design (secrets should not be cloned).
pub trait CBytes: Eq + PartialEq + Send + Sync {}

/// A Fixed Size Array of cryptographic bytes
///
/// This may be the compressed version of a public key for instance
pub trait FixedSizeCBytes<const LENGTH: usize>: CBytes + Sized {
    /// Key length
    const LENGTH: usize = LENGTH;

    /// Converts the given key into an array of LENGTH bytes.
    #[must_use]
    fn to_bytes(&self) -> [u8; LENGTH];

    /// Tries to create a key from the given slice of bytes into a key.
    fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoCoreError> {
        slice
            .try_into()
            .map_err(|_| CryptoCoreError::InvalidBytesLength)
            .and_then(Self::try_from_bytes)
    }

    /// Tries to create a key from the given array of bytes into a key.
    fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, CryptoCoreError>;
}

/// A Fixed Size Array of cryptographic bytes
/// that can be generated from a cryptographically secure random generator.
///
/// This may be a Nonce for instance
pub trait RandomFixedSizeCBytes<const LENGTH: usize>: FixedSizeCBytes<LENGTH> + Hash {
    /// Generate a new random array of LENGTH bytes
    #[must_use]
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self;

    /// Access the underlying slice of bytes (avoiding a copy).
    #[must_use]
    fn as_bytes(&self) -> &[u8];
}

/// Secret array of bytes such as a symmetric key or an elliptic curve private key.
///
/// These bytes must be zeroized on drop.
pub trait SecretCBytes<const LENGTH: usize>:
    RandomFixedSizeCBytes<LENGTH> + Zeroize + ZeroizeOnDrop
{
}
