//! Define the `SymmetricCrypto` and `DEM` traits and provide an implementation
//! based on the AES GCM algorithm. Define the `Block` and `Metadata` objects
//! to ease the use of AES on real data.

pub mod aes_256_gcm_pure;
pub mod key;
pub mod nonce;

mod block;
mod metadata;

pub use block::Block;
pub use metadata::BytesScanner;
pub use metadata::Metadata;

use crate::{CryptoCoreError, KeyTrait};
use generic_array::GenericArray;
use nonce::NonceTrait;
use rand_core::{CryptoRng, RngCore};
use std::vec::Vec;

/// Defines a symmetric encryption key.
pub trait SymKey: KeyTrait {
    /// Convert the given key into a byte slice.
    fn as_bytes(&self) -> &[u8];

    /// Convert the given bytes into a key.
    #[must_use]
    fn from_bytes(bytes: GenericArray<u8, Self::Length>) -> Self;
}

/// Defines a symmetric encryption scheme. If this scheme is authenticated,
/// the `MAC_LENGTH` will be greater than `0`.
pub trait SymmetricCrypto: Send + Sync {
    const MAC_LENGTH: usize;
    type Key: SymKey;
    type Nonce: NonceTrait;

    /// A short description of the scheme
    fn description() -> String;

    /// Encrypts a message using a secret key and a public nonce in combined
    /// mode.
    ///
    /// Append the MAC tag authenticating both the confidential and non
    /// confidential data (aad) to the ciphertext. Thus, the length of the
    /// encrypted data is the message length + `MAC_LENGTH`.
    ///
    /// It can also be used as a pur MAC by providing an empty message.
    ///
    /// # Parameters
    ///
    /// - `key`     : symmetric key to use for encryption
    /// - `bytes`   : message bytes to encrypt
    /// - `nonce`   : nonce to use
    /// - `aad`     : additional associated data, the same data must be used
    /// for decryption
    fn encrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError>;

    /// Decrypts a message in combined mode.
    ///
    /// Attempts to read a MAC appended to the ciphertext. The provided
    /// additional data must match those provided during encryption for the
    /// MAC to verify. Decryption will never be performed, even partially,
    /// before verification.
    ///
    /// # Parameters
    ///
    /// - `key`     : symmetric key to use
    /// - `bytes`   : encrypted bytes to decrypt (the MAC must be appended)
    /// - `nonce`   : nonce to use for decryption
    /// - `aad`     : additional associated data, the same data must be used
    /// for encryption
    fn decrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError>;
}

/// Defines a DEM based on a symmetric scheme as defined in section 9.1 of the
/// [ISO 2004](https://www.shoup.net/iso/std6.pdf).
pub trait Dem: SymmetricCrypto {
    /// Number of bytes added to the message length in the encapsulation.
    const ENCAPSULATION_OVERHEAD: usize = Self::Nonce::LENGTH + Self::MAC_LENGTH;

    /// Encapsulate data using the given symmetric key.
    ///
    /// - `rng`         : secure random number generator
    /// - `secret_key`  : secret symmetric key
    /// - `message`     : message to encapsulate
    /// - `aad`         : optional data to use in the authentication method,
    /// must use the same for decryption
    fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: &[u8],
        aad: Option<&[u8]>,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoCoreError>;

    /// Decapsulate data using the given symmetric key.
    ///
    /// - `secret_key`      : secret symmetric key
    /// - `encapsulation`   : message encapsulation
    /// - `aad`             : optional data to use in the authentication method,
    /// must use the same for encyption
    fn decaps(
        secret_key: &[u8],
        aad: Option<&[u8]>,
        encapsulation: &[u8],
    ) -> Result<Vec<u8>, CryptoCoreError>;
}
