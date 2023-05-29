//! Defines the `SymmetricCrypto` and `DEM` traits and provides an
//! implementation based on AES256-GCM.

pub mod aes_256_gcm_pure;
pub mod key;
pub mod nonce;

use core::fmt::Debug;
use std::vec::Vec;

use nonce::NonceTrait;

use crate::{reexport::rand_core::CryptoRngCore, CryptoCoreError, SecretKey};

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
    type SymmetricKey: SecretKey<KEY_LENGTH>;

    /// Encrypts data using the given symmetric key.
    ///
    /// - `rng`         : secure random number generator
    /// - `secret_key`  : secret symmetric key
    /// - `plaintext`   : plaintext message
    /// - `aad`         : optional data to use in the authentication method,
    /// must use the same for decryption
    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        secret_key: &Self::SymmetricKey,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError>;

    /// Decrypts data using the given symmetric key.
    ///
    /// - `secret_key`  : symmetric key
    /// - `ciphertext`  : ciphertext message
    /// - `aad`         : optional data to use in the authentication method,
    /// must use the same for encryption
    fn decrypt(
        secret_key: &Self::SymmetricKey,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError>;
}
