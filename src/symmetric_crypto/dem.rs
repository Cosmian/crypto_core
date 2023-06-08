use core::fmt::Debug;
use std::vec::Vec;

use aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload};

use crate::{CryptoCoreError, RandomFixedSizeCBytes, SecretCBytes};

/// Defines a DEM which is instantiable from a key
pub trait Instantiable<const KEY_LENGTH: usize>: Debug {
    type Secret: SecretCBytes<KEY_LENGTH>;

    /// Instantiate the DEM
    fn new(symmetric_key: &Self::Secret) -> Self;
}

/// Defines a DEM based on a symmetric scheme as defined in section 9.1 of the
/// [ISO 2004](https://www.shoup.net/iso/std6.pdf).
pub trait Dem<const KEY_LENGTH: usize, const NONCE_LENGTH: usize, const MAC_LENGTH: usize>:
    Instantiable<KEY_LENGTH>
{
    type AeadAlgo: Aead + KeyInit;
    type Nonce: RandomFixedSizeCBytes<NONCE_LENGTH>;

    /// Returns the RustCrypto Aead backend algorithm
    fn aead_backend<'a>(&'a self) -> &'a Self::AeadAlgo;

    /// Encrypts a plaintext using the given symmetric key.
    ///
    /// The authentication tag is appended to the ciphertext.
    ///
    /// - `nonce`       : the Nonce to use
    /// - `secret_key`  : secret symmetric key
    /// - `plaintext`   : plaintext message
    /// - `aad`         : optional data to use in the authentication method,
    /// must use the same for decryption
    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        self.aead_backend()
            .encrypt(
                nonce.as_bytes().into(),
                Payload {
                    msg: plaintext,
                    aad: aad.unwrap_or(b""),
                },
            )
            .map_err(|_| CryptoCoreError::EncryptionError)
    }

    /// Decrypts a ciphertext using the given symmetric key.
    ///
    /// The authentication tag must be appended to the ciphertext.
    ///
    /// - `secret_key`  : symmetric key
    /// - `ciphertext`  : ciphertext message
    /// - `aad`         : optional data to use in the authentication method,
    /// must use the same for encryption
    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        self.aead_backend()
            .decrypt(
                nonce.as_bytes().into(),
                Payload {
                    msg: &ciphertext,
                    aad: aad.unwrap_or(b""),
                },
            )
            .map_err(|_| CryptoCoreError::DecryptionError)
    }
}

pub trait DemInPlace<const KEY_LENGTH: usize, const NONCE_LENGTH: usize, const MAC_LENGTH: usize>:
    Debug
{
    type AeadInPlaceAlgo: AeadInPlace + KeyInit;
    type Nonce: RandomFixedSizeCBytes<NONCE_LENGTH>;

    /// Returns the RustCrypto Aead in place backend algorithm
    fn aead_in_place_backend<'a>(&'a self) -> &'a Self::AeadInPlaceAlgo;

    /// Encrypts a message in place using a secret key and a public nonce in
    /// detached mode: the tag authenticating both the confidential
    /// message and non-confidential data, are returned separately
    ///
    /// The tag length is `MAC_LENGTH`
    fn encrypt_in_place_detached(
        &self,
        nonce: &Self::Nonce,
        plaintext: &mut [u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        self.aead_in_place_backend()
            .encrypt_in_place_detached(nonce.as_bytes().into(), aad.unwrap_or_default(), plaintext)
            .map_err(|_| CryptoCoreError::EncryptionError)
            .map(|tag| tag.to_vec())
    }

    /// Decrypts a message in pace in detached mode.
    /// The bytes should not contain the authentication tag.
    ///
    /// The provided additional data must match those provided during encryption for
    /// the MAC to verify.
    ///
    /// Decryption will never be performed, even partially, before verification.
    fn decrypt_in_place_detached(
        &self,
        nonce: &Self::Nonce,
        bytes: &mut [u8],
        tag: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(), CryptoCoreError> {
        self.aead_in_place_backend()
            .decrypt_in_place_detached(
                nonce.as_bytes().into(),
                aad.unwrap_or_default(),
                bytes,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| CryptoCoreError::DecryptionError)
    }
}
