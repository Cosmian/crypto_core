pub mod dem;

use crate::{symmetric_crypto::SymmetricCrypto, CryptoBaseError};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    AeadInPlace, Aes256Gcm,
}; // Or `Aes128Gcm`
use std::{fmt::Display, vec::Vec};

// This implements AES 256 GCM, using a pure rust interface
// It will use the AES native interface on the CPU if available

pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const MAC_LENGTH: usize = 16;

pub type Key = crate::symmetric_crypto::key::Key<KEY_LENGTH>;
pub type Nonce = crate::symmetric_crypto::nonce::Nonce<NONCE_LENGTH>;

pub struct Aes256GcmCrypto;

impl Display for Aes256GcmCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Self::description())
    }
}

impl PartialEq for Aes256GcmCrypto {
    // `rng` is a random generator so you obviously can't
    // compare with other `rng` instance
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl SymmetricCrypto for Aes256GcmCrypto {
    type Key = Key;
    type Nonce = Nonce;

    const MAC_LENGTH: usize = MAC_LENGTH;

    fn description() -> String {
        format!(
            "AES 256 GCM pure Rust (key bits: {}, nonce bits: {}, tag bits: {})",
            KEY_LENGTH * 8,
            NONCE_LENGTH * 8,
            MAC_LENGTH * 8
        )
    }

    fn encrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        encrypt_combined(key, bytes, nonce, additional_data)
    }

    fn decrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBaseError> {
        decrypt_combined(key, bytes, nonce, additional_data)
    }
}

/// Encrypts a message using a secret key and a public nonce in combined mode:
/// the encrypted message, as well as a tag authenticating both the confidential
/// message and non-confidential data, are put into the encrypted result.
///
/// The total length of the encrypted data is the message length + `MAC_LENGTH`
pub fn encrypt_combined(
    key: &Key,
    bytes: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoBaseError> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let payload =
        additional_data.map_or_else(|| Payload::from(bytes), |aad| Payload { msg: bytes, aad });
    cipher
        .encrypt(GenericArray::from_slice(&nonce.0), payload)
        .map_err(|e| CryptoBaseError::EncryptionError(e.to_string()))
}

/// Encrypts a message in place using a secret key and a public nonce in
/// detached mode: The a tag authenticating both the confidential
/// message and non-confidential data, are returned separately
///
/// The tag length is `MAC_LENGTH`
pub fn encrypt_in_place_detached(
    key: &Key,
    bytes: &mut [u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoBaseError> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let additional_data = additional_data.unwrap_or_default();
    cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce.0), additional_data, bytes)
        .map_err(|e| CryptoBaseError::DecryptionError(e.to_string()))
        .map(|t| t.to_vec())
}

/// Decrypts a message in combined mode: the MAC is appended to the cipher text
///
/// The provided additional data must match those provided during encryption for
/// the MAC to verify.
///
/// Decryption will never be performed, even partially, before verification.
pub fn decrypt_combined(
    key: &Key,
    bytes: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoBaseError> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let payload =
        additional_data.map_or_else(|| Payload::from(bytes), |aad| Payload { msg: bytes, aad });
    cipher
        .decrypt(GenericArray::from_slice(&nonce.0), payload)
        .map_err(|e| CryptoBaseError::DecryptionError(e.to_string()))
}

/// Decrypts a message in pace in detached mode.
/// The bytes should not contain the authentication tag.
///
/// The provided additional data must match those provided during encryption for
/// the MAC to verify.
///
/// Decryption will never be performed, even partially, before verification.
pub fn decrypt_in_place_detached(
    key: &Key,
    bytes: &mut [u8],
    tag: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<(), CryptoBaseError> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key.0));
    let additional_data = additional_data.unwrap_or_default();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&nonce.0),
            additional_data,
            bytes,
            GenericArray::from_slice(tag),
        )
        .map_err(|e| CryptoBaseError::DecryptionError(e.to_string()))
}

#[cfg(test)]
mod tests {

    use crate::{
        entropy::CsRng,
        symmetric_crypto::{
            aes_256_gcm_pure::{
                decrypt_combined, decrypt_in_place_detached, encrypt_combined,
                encrypt_in_place_detached, Key, Nonce, KEY_LENGTH, MAC_LENGTH, NONCE_LENGTH,
            },
            nonce::NonceTrait,
        },
        CryptoBaseError,
    };

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::new();
        let key_1 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_1.0.len());
        let key_2 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_2.0.len());
        assert_ne!(key_1, key_2);
    }

    #[test]
    fn test_nonce() {
        let mut cs_rng = CsRng::new();
        let nonce_1 = Nonce::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_1.0.len());
        let nonce_2 = Nonce::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_2.0.len());
        assert_ne!(nonce_1, nonce_2);
    }

    #[test]
    fn test_random_bytes() {
        let mut cs_rng = CsRng::default();
        let size: usize = 1024;
        let random_bytes_1 = cs_rng.generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        let random_bytes_2 = cs_rng.generate_random_bytes(size);
        assert_eq!(size, random_bytes_1.len());
        assert_ne!(random_bytes_1, random_bytes_2);
    }

    #[test]
    fn test_encryption_decryption_combined() -> Result<(), CryptoBaseError> {
        let mut cs_rng = CsRng::new();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes(8192);
        let iv = Nonce::new(&mut cs_rng);
        // no additional data
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, None)?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, encrypted_result.as_slice(), &iv, None)?;
        assert_eq!(bytes, recovered);
        // additional data
        let ad = cs_rng.generate_random_bytes(42);
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, Some(&ad))?;
        assert_ne!(encrypted_result, bytes);
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, encrypted_result.as_slice(), &iv, Some(&ad))?;
        assert_eq!(bytes, recovered);
        Ok(())
    }

    #[test]
    fn test_encryption_decryption_detached() -> Result<(), CryptoBaseError> {
        let mut cs_rng = CsRng::new();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes(8192);
        let iv = Nonce::new(&mut cs_rng);
        // no additional data
        let mut data = bytes.clone();
        let tag = encrypt_in_place_detached(&key, &mut data, &iv, None)?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(&key, &mut data, &tag, &iv, None)?;
        assert_eq!(bytes, data);
        // // additional data
        let ad = cs_rng.generate_random_bytes(42);
        let mut data = bytes.clone();
        let tag = encrypt_in_place_detached(&key, &mut data, &iv, Some(&ad))?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(&key, &mut data, &tag, &iv, Some(&ad))?;
        assert_eq!(bytes, data);
        Ok(())
    }
}
