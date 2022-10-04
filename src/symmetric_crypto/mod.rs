//! Define the `SymmetricCrypto` and `DEM` traits and provide an implementation
//! based on the AES GCM algorithm. Define the `Block` and `Metadata` objects
//! to ease the use of AES on real data.

pub mod aes_256_gcm_pure;
pub mod key;
pub mod nonce;

mod metadata;

pub use metadata::BytesScanner;
pub use metadata::Metadata;

use crate::{CryptoCoreError, KeyTrait};
use core::{fmt::Debug, hash::Hash};
use nonce::NonceTrait;
use rand_core::{CryptoRng, RngCore};
use std::vec::Vec;

/// Defines a symmetric encryption key.
pub trait SymKey<const LENGTH: usize>: KeyTrait<LENGTH> + Hash {
    /// Converts the given key into a byte slice.
    #[must_use]
    fn as_bytes(&self) -> &[u8];

    /// Consumes the key to return the underlying bytes.
    #[must_use]
    fn into_bytes(self) -> [u8; LENGTH];

    /// Converts the given bytes into a key.
    #[must_use]
    fn from_bytes(bytes: [u8; LENGTH]) -> Self;
}

/// Defines a DEM based on a symmetric scheme as defined in section 9.1 of the
/// [ISO 2004](https://www.shoup.net/iso/std6.pdf).
pub trait Dem<const KEY_LENGTH: usize>: Debug + PartialEq {
    /// Number of bytes added to the message length in the encapsulation.
    const ENCRYPTION_OVERHEAD: usize = Self::Nonce::LENGTH + Self::MAC_LENGTH;

    /// MAC tag length
    const MAC_LENGTH: usize;

    /// Symmetric key length
    const KEY_LENGTH: usize = KEY_LENGTH;

    /// Associated nonce type
    type Nonce: NonceTrait;

    /// Associated key type
    type Key: SymKey<KEY_LENGTH>;

    /// Encrypts data using the given symmetric key.
    ///
    /// - `rng`         : secure random number generator
    /// - `secret_key`  : secret symmetric key
    /// - `plaintext`   : plaintext message
    /// - `aad`         : optional data to use in the authentication method,
    /// must use the same for decryption
    fn encrypt<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: &Self::Key,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError>;

    /// Decrypts data using the given symmetric key.
    ///
    /// - `secret_key`  : symmetric key
    /// - `ciphertext`  : ciphertext message
    /// - `aad`         : optional data to use in the authentication method,
    /// must use the same for encyption
    fn decrypt(
        secret_key: &Self::Key,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError>;
}
