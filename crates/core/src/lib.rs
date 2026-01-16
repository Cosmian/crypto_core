//! This crate implements crypto primitives which are used in many other Cosmian
//! cryptographic crates.

mod error;
mod key;
mod secret;

#[cfg(any(feature = "curve25519", feature = "nist_curves", feature = "rsa"))]
mod asymmetric_crypto;

#[cfg(feature = "blake")]
pub mod blake2;

#[cfg(feature = "ecies")]
mod ecies;

#[cfg(any(feature = "rsa", feature = "nist_curves"))]
mod pkcs8_fix;

#[cfg(any(feature = "aes", feature = "chacha", feature = "rfc5649"))]
mod symmetric_crypto;

pub mod bytes_ser_de;

#[macro_use]
pub mod traits;

#[cfg(feature = "macro")]
#[macro_use]
pub mod bytes;

#[cfg(feature = "sha3")]
#[macro_use]
pub mod kdf;

pub mod reexport {
    #[cfg(any(feature = "aes", feature = "chacha"))]
    pub use aead;
    #[cfg(feature = "certificate")]
    pub use pkcs8;
    pub use rand_core;
    #[cfg(feature = "curve25519")]
    pub use signature;
    #[cfg(feature = "sha3")]
    pub use tiny_keccak;
    #[cfg(feature = "certificate")]
    pub use x509_cert;
    pub mod zeroize {
        pub use zeroize::*;
    }
}

pub use error::CryptoCoreError;
pub use key::SymmetricKey;
pub use secret::Secret;

#[cfg(any(feature = "curve25519", feature = "nist_curves", feature = "rsa"))]
pub use asymmetric_crypto::*;

#[cfg(feature = "ecies")]
pub use ecies::*;

#[cfg(any(feature = "aes", feature = "chacha"))]
pub use symmetric_crypto::*;

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Use `ChaCha` with 12 rounds as cryptographic RNG.
pub type CsRng = rand_chacha::ChaCha12Rng;

/// Shuffles the given slice in a destructive way.
pub fn shuffle_in_place<X>(xs: &mut [X], rng: &mut impl CryptoRngCore) {
    for i in 0..xs.len() {
        let j = rng.next_u32() as usize % xs.len();
        xs.swap(i, j);
    }
}

/// Returns a vector containing a shuffled copy of the given elements.
pub fn shuffle<X: Clone>(xs: &[X], rng: &mut impl CryptoRngCore) -> Vec<X> {
    let mut res = xs.to_vec();
    shuffle_in_place(&mut res, rng);
    res
}

/// Cryptographic bytes
///
/// The bytes should be thread-safe and comparable.
/// The bytes are NOT cloneable by design (secrets should not be cloned).
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
            .map_err(|_| CryptoCoreError::TryFromSliceError {
                expected: Self::LENGTH,
                given: slice.len(),
            })
            .and_then(Self::try_from_bytes)
    }

    /// Tries to create a key from the given array of bytes into a key.
    fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, CryptoCoreError>;
}

/// A Fixed Size Array of cryptographic bytes that can be generated from a
/// cryptographically secure random generator.
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
