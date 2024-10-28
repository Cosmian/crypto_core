use core::fmt::Debug;
use std::{
    ops::{Deref, Sub},
    vec::Vec,
};

use aead::{
    consts::{U4, U5},
    generic_array::{ArrayLength, GenericArray},
    stream::{DecryptorBE32, DecryptorLE31, EncryptorBE32, EncryptorLE31},
    Aead, AeadCore, AeadInPlace, KeyInit, Payload,
};

use crate::{CryptoCoreError, RandomFixedSizeCBytes, SecretCBytes};

/// Defines a DEM which is instantiable from a key
pub trait Instantiable<const KEY_LENGTH: usize>: Debug {
    type Secret: SecretCBytes<KEY_LENGTH>;

    /// Instantiate the DEM
    fn new(symmetric_key: &Self::Secret) -> Self;
}

/// Defines a DEM based on a symmetric scheme as defined in section 9.1 of the
/// [ISO 2004](https://www.shoup.net/iso/std6.pdf).
pub trait Dem<
    const KEY_LENGTH: usize,
    const NONCE_LENGTH: usize,
    const MAC_LENGTH: usize,
    RustCryptoBackend,
>: Instantiable<KEY_LENGTH> + Deref<Target = RustCryptoBackend> where
    RustCryptoBackend: Aead + KeyInit,
{
    type Nonce: RandomFixedSizeCBytes<NONCE_LENGTH>;

    /// Encrypts a plaintext using the given symmetric key.
    ///
    /// The authentication tag is appended to the ciphertext.
    ///
    /// - `nonce`       : the Nonce to use
    /// - `plaintext`   : plaintext message
    /// - `aad`         : optional data to use in the authentication method,
    ///   must use the same for decryption
    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        self.deref()
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
    /// - `nonce`       : the Nonce to use
    /// - `ciphertext`  : ciphertext message
    /// - `aad`         : optional data to use in the authentication method,
    ///   must use the same for encryption
    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        self.deref()
            .decrypt(
                nonce.as_bytes().into(),
                Payload {
                    msg: ciphertext,
                    aad: aad.unwrap_or(b""),
                },
            )
            .map_err(|_| CryptoCoreError::DecryptionError)
    }
}

/// Defines a DEM based on a symmetric scheme as defined in section 9.1 of the
/// [ISO 2004](https://www.shoup.net/iso/std6.pdf)
/// that allows encryption and decryption in place.
pub trait DemInPlace<
    const KEY_LENGTH: usize,
    const NONCE_LENGTH: usize,
    const MAC_LENGTH: usize,
    RustCryptoBackend,
>: Instantiable<KEY_LENGTH> + Deref<Target = RustCryptoBackend> where
    RustCryptoBackend: AeadInPlace + KeyInit,
{
    type Nonce: RandomFixedSizeCBytes<NONCE_LENGTH>;

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
        self.deref()
            .encrypt_in_place_detached(nonce.as_bytes().into(), aad.unwrap_or_default(), plaintext)
            .map_err(|_| CryptoCoreError::EncryptionError)
            .map(|tag| tag.to_vec())
    }

    /// Decrypts a message in pace in detached mode.
    /// The bytes should not contain the authentication tag.
    ///
    /// The provided additional data must match those provided during encryption
    /// for the MAC to verify.
    ///
    /// Decryption will never be performed, even partially, before verification.
    fn decrypt_in_place_detached(
        &self,
        nonce: &Self::Nonce,
        bytes: &mut [u8],
        tag: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(), CryptoCoreError> {
        self.deref()
            .decrypt_in_place_detached(
                nonce.as_bytes().into(),
                aad.unwrap_or_default(),
                bytes,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| CryptoCoreError::DecryptionError)
    }
}

/// Defines a DEM based on a symmetric scheme as defined in section 9.1 of the
/// [ISO 2004](https://www.shoup.net/iso/std6.pdf)
/// that allows encrypting and decrypting a stream.
pub trait DemStream<
    const KEY_LENGTH: usize,
    const NONCE_LENGTH: usize,
    const MAC_LENGTH: usize,
    RustCryptoBackend,
>: Instantiable<KEY_LENGTH> + Sized + Deref<Target = RustCryptoBackend> where
    RustCryptoBackend: AeadInPlace + KeyInit,
    <RustCryptoBackend as AeadCore>::NonceSize: Sub<U5>,
    <RustCryptoBackend as AeadCore>::NonceSize: Sub<U4>,
    <<RustCryptoBackend as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
    <<RustCryptoBackend as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>,
{
    type Nonce: RandomFixedSizeCBytes<NONCE_LENGTH>;

    /// Returns the `RustCrypto` Aead in place backend algorithm with stream
    /// capabilities
    fn into_aead_stream_backend(self) -> RustCryptoBackend;

    fn into_stream_encryptor_be32(self, nonce: &Self::Nonce) -> EncryptorBE32<RustCryptoBackend> {
        EncryptorBE32::from_aead(
            self.into_aead_stream_backend(),
            nonce.as_bytes()[0..NONCE_LENGTH - 5].into(),
        )
    }

    fn into_stream_decryptor_be32(self, nonce: &Self::Nonce) -> DecryptorBE32<RustCryptoBackend> {
        DecryptorBE32::from_aead(
            self.into_aead_stream_backend(),
            nonce.as_bytes()[0..NONCE_LENGTH - 5].into(),
        )
    }

    fn into_stream_encryptor_le31(self, nonce: &Self::Nonce) -> EncryptorLE31<RustCryptoBackend> {
        EncryptorLE31::from_aead(
            self.into_aead_stream_backend(),
            nonce.as_bytes()[0..NONCE_LENGTH - 4].into(),
        )
    }

    fn into_stream_decryptor_le31(self, nonce: &Self::Nonce) -> DecryptorLE31<RustCryptoBackend> {
        DecryptorLE31::from_aead(
            self.into_aead_stream_backend(),
            nonce.as_bytes()[0..NONCE_LENGTH - 4].into(),
        )
    }
}
