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

use reexport::rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::error::CryptoCoreError;

/// Use `ChaCha` with 12 rounds as cryptographic RNG.
pub type CsRng = rand_chacha::ChaCha12Rng;

/// A cryptographic key.
///
/// The key should be thread-safe, clonable, comparable, and zeroizeable.
pub trait Key: Clone + Eq + PartialEq + Send + Sync + Zeroize + ZeroizeOnDrop {}

/// A Fixed Size Key
///
/// This may be the compressed form of a public key when using elliptic curves
pub trait FixedSizeKey<const LENGTH: usize>: Key + Sized {
    /// Key length
    const LENGTH: usize = LENGTH;

    /// Converts the given key into a vector of LENGTH bytes.
    #[must_use]
    fn to_bytes(&self) -> Vec<u8>;

    /// Tries to create a key from the given slice of bytes into a key.
    fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoCoreError>;
}

/// A secret key such as a symmetric key or an elliptic curve private key.
pub trait SecretKey<const LENGTH: usize>: FixedSizeKey<LENGTH> {
    /// Generates a new random key.
    #[must_use]
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self;

    /// Access the underlying slice of bytes (avoid copy).
    #[must_use]
    fn as_slice(&self) -> &[u8];
}

// /// Cryptographic key.
// pub trait KeyTrait<const LENGTH: usize>:
//     Clone + Eq + PartialEq + Send + Sized + Sync + Zeroize + ZeroizeOnDrop
// {
//     /// Key length
//     const LENGTH: usize = LENGTH;

//     /// Generates a new random key.
//     #[must_use]
//     fn new<R: CryptoRngCore>(rng: &mut R) -> Self;

//     /// Converts the given key into a vector of bytes.
//     #[must_use]
//     fn to_bytes(&self) -> [u8; LENGTH];

//     /// Converts to a slice of bytes without copy.
//     #[must_use]
//     fn as_slice(&self) -> &[u8];

//     /// Tries to create a key from the given slice bytes into a key.
//     fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError>;

//     /// Create a key from the given array of bytes
//     fn from_bytes(bytes: [u8; LENGTH]) -> Self;
// }
