//! This crate implements crypto primitives which are used in many other
//! Cosmian cryptographic resources.

#[cfg(feature = "curve25519")]
mod asymmetric_crypto;
#[cfg(feature = "blake")]
pub mod blake2;
#[cfg(feature = "ser")]
pub mod bytes_ser_de;
#[cfg(feature = "ecies")]
mod ecies;
#[cfg(feature = "sha3")]
pub mod kdf;
#[cfg(any(feature = "aes", feature = "chacha", feature = "rfc5649"))]
mod symmetric_crypto;

mod error;
pub mod reexport {
    #[cfg(any(feature = "aes", feature = "chacha"))]
    pub use aead;
    pub use rand_core;
    #[cfg(feature = "curve25519")]
    pub use signature;
    #[cfg(feature = "sha3")]
    pub use tiny_keccak;
    pub use zeroize;
}

#[cfg(feature = "curve25519")]
pub use asymmetric_crypto::*;
#[cfg(feature = "ecies")]
pub use ecies::*;
#[cfg(feature = "sha3")]
pub use kdf::*;
use reexport::rand_core::CryptoRngCore;
#[cfg(any(feature = "aes", feature = "chacha"))]
pub use symmetric_crypto::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::error::CryptoCoreError;

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
    /// Key length.
    const LENGTH: usize = LENGTH;

    /// Converts the given key into an array of LENGTH bytes.
    #[must_use]
    fn to_bytes(&self) -> [u8; LENGTH];

    /// Tries to create a key from the given slice of bytes into a key.
    fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoCoreError> {
        slice
            .try_into()
            .map_err(CryptoCoreError::TryFromSliceError)
            .and_then(Self::try_from_bytes)
    }

    /// Tries to create a key from the given array of bytes into a key.
    fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, CryptoCoreError>;
}

/// A Fixed Size Array of cryptographic bytes
/// that can be generated from a cryptographically secure random generator.
///
/// This may be a Nonce for instance
pub trait RandomFixedSizeCBytes<const LENGTH: usize>: FixedSizeCBytes<LENGTH> {
    /// Generates a new random array of LENGTH bytes
    #[must_use]
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self;

    /// Returns a slice over the array bytes.
    fn as_bytes(&self) -> &[u8];
}

/// Secret array of bytes such as a symmetric key or an elliptic curve private
/// key.
///
/// These bytes must be zeroized on drop.
pub trait SecretCBytes<const LENGTH: usize>:
    RandomFixedSizeCBytes<LENGTH> + Zeroize + ZeroizeOnDrop
{
}
