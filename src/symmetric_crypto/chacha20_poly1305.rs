//! This file exposes the Chacha20 Poly1305 implemented
//! in RustCrypto (https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)

use chacha20poly1305::ChaCha20Poly1305 as ChaCha20Poly1305Lib;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use crate::SecretKey;
use crate::symmetric_crypto::nonce::NonceTrait;

/// Use a 256-bit AES key.
pub const KEY_LENGTH: usize = 32;

/// Use a 96-bit nonce.
pub const NONCE_LENGTH: usize = 12;

/// Use a 128-bit MAC tag.
pub const MAC_LENGTH: usize = 16;

#[derive(Debug, PartialEq, Eq)]
struct ChaCha20Poly1305;

use super::{Dem, key::SymmetricKey, nonce::Nonce};

impl Dem<32> for ChaCha20Poly1305 {

    type SymmetricKey = SymmetricKey<KEY_LENGTH>;
    type Nonce = Nonce<NONCE_LENGTH>;

    const ENCRYPTION_OVERHEAD: usize = Self::Nonce::LENGTH + Self::MAC_LENGTH;
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn encrypt<R: rand_chacha::rand_core::CryptoRngCore>(
        rng: &mut R,
        secret_key: &Self::SymmetricKey,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, crate::CryptoCoreError> {
                    let key = GenericArray::from_slice(secret_key.as_bytes());
            let nonce = GenericArray::from_slice($nonce);
            let payload = Payload {
                msg: $plaintext,
                aad: $aad,
            };

            let ciphertext = ChaCha20Poly1305Lib::new(key).encrypt_in_place_detached(nonce, payload).unwrap();

            let tag_begins = ciphertext.len() - 16;

            Ok(())
    }

    fn decrypt(
        secret_key: &Self::SymmetricKey,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, crate::CryptoCoreError> {
        todo!()
    }
}


see https://github.com/RustCrypto/AEADs/blob/master/chacha20poly1305/tests/lib.rs


/// Encrypts a message using a secret key and a public nonce in combined mode:
/// the encrypted message, as well as a tag authenticating both the confidential
/// message and non-confidential data, are put into the encrypted result.
///
/// The total length of the encrypted data is the message length + `MAC_LENGTH`
pub fn encrypt_combined(
    key: &[u8],
    bytes: &[u8],
    nonce: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError> {
    let payload =
        additional_data.map_or_else(|| Payload::from(bytes), |aad| Payload { msg: bytes, aad });
    ChaCha20Poly1305Lib::new(GenericArray::from_slice(key))
        .encrypt(GenericArray::from_slice(nonce), payload)
        .map_err(|_| CryptoCoreError::EncryptionError)
}

/// Encrypts a message in place using a secret key and a public nonce in
/// detached mode: the tag authenticating both the confidential
/// message and non-confidential data, are returned separately
///
/// The tag length is `MAC_LENGTH`
pub fn encrypt_in_place_detached(
    key: &[u8],
    bytes: &mut [u8],
    nonce: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError> {
    ChaCha20Poly1305Lib::new(GenericArray::from_slice(key))
        .encrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            additional_data.unwrap_or_default(),
            bytes,
        )
        .map_err(|_| CryptoCoreError::DecryptionError)
        .map(|t| t.to_vec())
}

/// Decrypts a message in combined mode: the MAC is appended to the cipher text
///
/// The provided additional data must match those provided during encryption for
/// the MAC to verify.
///
/// Decryption will never be performed, even partially, before verification.
pub fn decrypt_combined(
    key: &[u8],
    msg: &[u8],
    nonce: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError> {
    let payload = additional_data.map_or_else(|| Payload::from(msg), |aad| Payload { msg, aad });
    ChaCha20Poly1305Lib::new(GenericArray::from_slice(key))
        .decrypt(GenericArray::from_slice(nonce), payload)
        .map_err(|_| CryptoCoreError::DecryptionError)
}

/// Decrypts a message in pace in detached mode.
/// The bytes should not contain the authentication tag.
///
/// The provided additional data must match those provided during encryption for
/// the MAC to verify.
///
/// Decryption will never be performed, even partially, before verification.
pub fn decrypt_in_place_detached(
    key: &[u8],
    bytes: &mut [u8],
    tag: &[u8],
    nonce: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<(), CryptoCoreError> {
    ChaCha20Poly1305Lib::new(GenericArray::from_slice(key))
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            additional_data.unwrap_or_default(),
            bytes,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| CryptoCoreError::DecryptionError)
}