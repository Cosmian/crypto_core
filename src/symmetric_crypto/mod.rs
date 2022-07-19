//! Define traits used in this module.
//!
//! The `SymmetricCrypto` trait defines a symmetric encryption scheme. The
//! `Dem` trait defines a DEM based on a symmetric scheme defined as described
//! in the previous trait.

pub mod aes_256_gcm_pure;
pub mod key;
pub mod nonce;

mod block;
mod metadata;

pub use block::Block;
pub use metadata::Metadata;

use crate::{CryptoBaseError, KeyTrait};
use nonce::NonceTrait;
use rand_core::{CryptoRng, RngCore};
use std::vec::Vec;

pub const MIN_DATA_LENGTH: usize = 1;

/// Defines a symmetric encryption scheme. If this scheme is authenticated,
/// the `MAC_LENGTH` will be greater than `0`.
pub trait SymmetricCrypto: Send + Sync {
    const MAC_LENGTH: usize;
    type Key: KeyTrait;
    type Nonce: NonceTrait;

    /// A short description of the scheme
    fn description() -> String;

    /// Encrypts a message using a secret key and a public nonce in combined
    /// mode: the encrypted message, as well as a tag authenticating both
    /// the confidential message and non-confidential data, are put into the
    /// encrypted result.
    ///
    /// The total length of the encrypted data is the message length +
    /// `MAC_LENGTH`
    ///
    /// This function encrypts then tag: it can also be used as a MAC, with an
    /// empty message.
    fn encrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBaseError>;

    /// Decrypts a message in combined mode: the MAC is appended to the cipher
    /// text
    ///
    /// The provided additional data must match those provided during encryption
    /// for the MAC to verify.
    ///
    /// Decryption will never be performed, even partially, before verification.
    fn decrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBaseError>;
}

pub trait Dem: SymmetricCrypto {
    /// Number of bytes added to the message length in the ciphertext
    const ENCRYPTION_OVERHEAD: usize = Self::Key::LENGTH + Self::MAC_LENGTH;

    /// Encapsulate data using a KEM-generated secret key `K`.
    ///
    /// - `rng` : secure random number generator
    /// - `secret_key`      : KEM-generated secret key
    /// - `additional_data` : optional data to use in the authentication method
    /// - `message`         : message to encapsulate
    fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: &[u8],
        additional_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError>;

    /// Decapsulate using a KEM-generated secret key `K`.
    ///
    /// - `secret_key`      : KEM-generated secret key
    /// - `additional_data` : optional data to use in the authentication method
    /// - `encapsulation`   : encapsulation of the message
    fn decaps(
        secret_key: &[u8],
        additional_data: Option<&[u8]>,
        encapsulation: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError>;
}
