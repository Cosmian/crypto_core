//! This crate implements crypto primitives which are used in many other
//! Cosmian cryptographic resources.

pub mod asymmetric_crypto;
pub mod bytes_ser_de;
pub mod ecies;
mod error;
pub mod kdf;
pub mod reexport {
    // reexport `rand_core` so that the PRNGs implement the correct version of
    // the traits
    pub use rand_chacha::rand_core;
    // reexport the signature Traits
    pub use signature;
}
pub mod symmetric_crypto;

use reexport::rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::error::CryptoCoreError;
pub use ecies::Ecies;

/// Use `ChaCha` with 12 rounds as cryptographic RNG.
pub type CsRng = rand_chacha::ChaCha12Rng;

/// Cryptographic bytes
///
/// The bytes should be thread-safe, clonable and comparable.
pub trait CBytes: Clone + Eq + PartialEq + Send + Sync {}

/// A Fixed Size Array of cryptographic bytes
///
/// This may be a Salt, a Nonce,
/// the compressed form of a public key when using elliptic curves, etc...
pub trait FixedSizeCBytes<const LENGTH: usize>: CBytes + Sized {
    /// Key length
    const LENGTH: usize = LENGTH;

    /// Converts the given key into a vector of LENGTH bytes.
    #[must_use]
    fn to_bytes(&self) -> [u8; LENGTH];

    /// Tries to create a key from the given slice of bytes into a key.
    fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoCoreError> {
        slice
            .try_into()
            .map_err(|_| CryptoCoreError::InvalidBytesLength)
            .and_then(Self::try_from_bytes)
    }

    /// Tries to create a key from the given bytes into a key.
    fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, CryptoCoreError>;
}

/// Secret array of bytes such as a symmetric key or an elliptic curve private key.
///
/// These bytes can be generated from entropy and must be zeroized on drop
pub trait SecretCBytes<const LENGTH: usize>:
    FixedSizeCBytes<LENGTH> + Zeroize + ZeroizeOnDrop
{
    /// Generates a new random key.
    #[must_use]
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self;

    /// Access the underlying slice of bytes (avoiding a copy).
    #[must_use]
    fn as_bytes(&self) -> &[u8];
}
