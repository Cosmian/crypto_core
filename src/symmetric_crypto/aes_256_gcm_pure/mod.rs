//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 256 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use crate::{
    symmetric_crypto::{nonce::NonceTrait, SymmetricCrypto},
    CryptoCoreError,
};
use aes::cipher::Unsigned;
use aes_gcm::{
    aead::{Aead, NewAead, Payload},
    AeadInPlace, Aes256Gcm,
};
use generic_array::{typenum, GenericArray};
use std::fmt::Display;

pub mod dem;

/// Use a 256-bit AES key
pub type KeyLength = typenum::U32;

/// Use a 96-bit nonce
pub const NONCE_LENGTH: usize = 12;

/// Use a 128-bit MAC tag
pub const MAC_LENGTH: usize = 16;

pub type Key = crate::symmetric_crypto::key::Key<KeyLength>;

pub type Nonce = crate::symmetric_crypto::nonce::Nonce<NONCE_LENGTH>;

/// Structure implementing `SymmetricCrypto` and the `DEM` interfaces based on
/// AES 256 GCM.
pub struct Aes256GcmCrypto;

impl Display for Aes256GcmCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Self::description())
    }
}

impl SymmetricCrypto for Aes256GcmCrypto {
    type Key = Key;
    type Nonce = Nonce;

    const MAC_LENGTH: usize = MAC_LENGTH;

    fn description() -> String {
        format!(
            "AES 256 GCM pure Rust (key bits: {}, nonce bits: {}, tag bits: {})",
            KeyLength::to_usize() * 8,
            NONCE_LENGTH * 8,
            MAC_LENGTH * 8
        )
    }

    fn encrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        encrypt_combined(key, bytes, nonce, additional_data)
    }

    fn decrypt(
        key: &Self::Key,
        bytes: &[u8],
        nonce: &Self::Nonce,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
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
) -> Result<Vec<u8>, CryptoCoreError> {
    let payload =
        additional_data.map_or_else(|| Payload::from(bytes), |aad| Payload { msg: bytes, aad });
    Aes256Gcm::new(key)
        .encrypt(GenericArray::from_slice(nonce.as_slice()), payload)
        .map_err(|e| CryptoCoreError::EncryptionError(e.to_string()))
}

/// Encrypts a message in place using a secret key and a public nonce in
/// detached mode: the tag authenticating both the confidential
/// message and non-confidential data, are returned separately
///
/// The tag length is `MAC_LENGTH`
pub fn encrypt_in_place_detached(
    key: &Key,
    bytes: &mut [u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError> {
    Aes256Gcm::new(key)
        .encrypt_in_place_detached(
            GenericArray::from_slice(nonce.as_slice()),
            additional_data.unwrap_or_default(),
            bytes,
        )
        .map_err(|e| CryptoCoreError::DecryptionError(e.to_string()))
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
    msg: &[u8],
    nonce: &Nonce,
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError> {
    let payload = additional_data.map_or_else(|| Payload::from(msg), |aad| Payload { msg, aad });
    Aes256Gcm::new(key)
        .decrypt(GenericArray::from_slice(nonce.as_slice()), payload)
        .map_err(|e| CryptoCoreError::DecryptionError(e.to_string()))
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
) -> Result<(), CryptoCoreError> {
    Aes256Gcm::new(key)
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce.as_slice()),
            additional_data.unwrap_or_default(),
            bytes,
            GenericArray::from_slice(tag),
        )
        .map_err(|e| CryptoCoreError::DecryptionError(e.to_string()))
}

#[cfg(test)]
mod tests {

    use crate::{
        entropy::CsRng,
        symmetric_crypto::{
            aes_256_gcm_pure::{
                decrypt_combined, decrypt_in_place_detached, encrypt_combined,
                encrypt_in_place_detached, Key, Nonce, MAC_LENGTH,
            },
            nonce::NonceTrait,
        },
        CryptoCoreError,
    };
    use generic_array::typenum::{U42, U8192};

    #[test]
    fn test_encryption_decryption_combined() -> Result<(), CryptoCoreError> {
        let mut cs_rng = CsRng::new();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes::<U8192>();
        let iv = Nonce::new(&mut cs_rng);
        // no additional data
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, None)?;
        assert_ne!(encrypted_result, bytes.to_vec());
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, &encrypted_result, &iv, None)?;
        assert_eq!(bytes.to_vec(), recovered);
        // additional data
        let aad = cs_rng.generate_random_bytes::<U42>();
        let encrypted_result = encrypt_combined(&key, &bytes, &iv, Some(&aad))?;
        assert_ne!(encrypted_result, bytes.to_vec());
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, &encrypted_result, &iv, Some(&aad))?;
        assert_eq!(bytes.to_vec(), recovered);
        // data should not be recovered if the AAD is modified
        let aad = cs_rng.generate_random_bytes::<U42>();
        let recovered = decrypt_combined(&key, &encrypted_result, &iv, Some(&aad));
        assert_ne!(Ok(bytes.to_vec()), recovered);
        // data should not be recovered if the key is modified
        let new_key = Key::new(&mut cs_rng);
        let recovered = decrypt_combined(&new_key, &encrypted_result, &iv, Some(&aad));
        assert_ne!(Ok(bytes.to_vec()), recovered);
        Ok(())
    }

    #[test]
    fn test_encryption_decryption_detached() -> Result<(), CryptoCoreError> {
        let mut cs_rng = CsRng::new();
        let key = Key::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes::<U8192>();
        let iv = Nonce::new(&mut cs_rng);
        // no additional data
        let mut data = bytes;
        let tag = encrypt_in_place_detached(&key, &mut data, &iv, None)?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(&key, &mut data, &tag, &iv, None)?;
        assert_eq!(bytes, data);
        // // additional data
        let ad = cs_rng.generate_random_bytes::<U42>();
        let mut data = bytes;
        let tag = encrypt_in_place_detached(&key, &mut data, &iv, Some(&ad))?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(&key, &mut data, &tag, &iv, Some(&ad))?;
        assert_eq!(bytes, data);
        Ok(())
    }
}
