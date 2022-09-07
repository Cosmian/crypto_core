//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 256 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use crate::{
    symmetric_crypto::{nonce::NonceTrait, Dem, SymKey},
    CryptoCoreError,
};
use aes_gcm::{
    aead::{Aead, Payload},
    aes::cipher::generic_array::GenericArray,
    AeadInPlace, Aes256Gcm, KeyInit,
};
use rand_core::{CryptoRng, RngCore};

use super::{key::Key, nonce::Nonce};

/// Use a 256-bit AES key
const KEY_LENGTH: usize = 32;

/// Use a 96-bit nonce
const NONCE_LENGTH: usize = 12;

/// Use a 128-bit MAC tag
const MAC_LENGTH: usize = 16;

/// A 96-bit nonce restricts the plaintext size to 4096 bytes
const MAX_PLAINTEXT_LENGTH: usize = 4096;

/// Structure implementing `SymmetricCrypto` and the `DEM` interfaces based on
/// AES 256 GCM.
#[derive(Debug, PartialEq, Eq)]
pub struct Aes256GcmCrypto;

impl Dem<KEY_LENGTH> for Aes256GcmCrypto {
    const ENCRYPTION_OVERHEAD: usize = Self::Nonce::LENGTH + Self::MAC_LENGTH;

    const MAC_LENGTH: usize = MAC_LENGTH;

    type Key = Key<KEY_LENGTH>;

    type Nonce = Nonce<NONCE_LENGTH>;

    fn encrypt<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret_key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        if plaintext.len() > MAX_PLAINTEXT_LENGTH {
            return Err(CryptoCoreError::InvalidSize(format!(
                "Plaintext is too large ({} bytes), max size: {} ",
                plaintext.len(),
                MAX_PLAINTEXT_LENGTH
            )));
        }
        let nonce = Self::Nonce::new(rng);
        // allocate correct byte number
        let mut res: Vec<u8> = Vec::with_capacity(plaintext.len() + Self::ENCRYPTION_OVERHEAD);
        res.extend_from_slice(nonce.as_bytes());
        res.append(
            &mut encrypt_combined(
                secret_key.as_bytes(),
                plaintext,
                nonce.as_bytes(),
                additional_data,
            )
            .map_err(|err| CryptoCoreError::EncryptionError(err.to_string()))?,
        );
        Ok(res)
    }

    fn decrypt(
        secret_key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        if ciphertext.len() < Self::ENCRYPTION_OVERHEAD {
            return Err(CryptoCoreError::InvalidSize(format!(
                "Ciphertext is too small ({} bytes), min size: {}",
                ciphertext.len(),
                Self::ENCRYPTION_OVERHEAD
            )));
        }
        if ciphertext.len() > MAX_PLAINTEXT_LENGTH + Self::ENCRYPTION_OVERHEAD {
            return Err(CryptoCoreError::InvalidSize(format!(
                "Ciphertext is too large ({} bytes), max size: {} ",
                ciphertext.len(),
                MAX_PLAINTEXT_LENGTH + Self::ENCRYPTION_OVERHEAD
            )));
        }
        // Read the nonce used for encryption. We know this will not fail since
        // Self::Nonce::LENGTH < Self::ENCRYPTOION_OVERHEAD
        let nonce = Self::Nonce::try_from(&ciphertext[..Self::Nonce::LENGTH])?;
        decrypt_combined(
            secret_key.as_bytes(),
            &ciphertext[Self::Nonce::LENGTH..],
            nonce.as_bytes(),
            additional_data,
        )
        .map_err(|err| CryptoCoreError::EncryptionError(err.to_string()))
    }
}

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
    Aes256Gcm::new(GenericArray::from_slice(key))
        .encrypt(GenericArray::from_slice(nonce), payload)
        .map_err(|e| CryptoCoreError::EncryptionError(e.to_string()))
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
    Aes256Gcm::new(GenericArray::from_slice(key))
        .encrypt_in_place_detached(
            GenericArray::from_slice(nonce),
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
    key: &[u8],
    msg: &[u8],
    nonce: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError> {
    let payload = additional_data.map_or_else(|| Payload::from(msg), |aad| Payload { msg, aad });
    Aes256Gcm::new(GenericArray::from_slice(key))
        .decrypt(GenericArray::from_slice(nonce), payload)
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
    key: &[u8],
    bytes: &mut [u8],
    tag: &[u8],
    nonce: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<(), CryptoCoreError> {
    Aes256Gcm::new(GenericArray::from_slice(key))
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
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
                encrypt_in_place_detached, Aes256GcmCrypto, Nonce, KEY_LENGTH, MAC_LENGTH,
                NONCE_LENGTH,
            },
            key::Key,
            nonce::NonceTrait,
            Dem, SymKey,
        },
        CryptoCoreError, KeyTrait,
    };

    #[test]
    fn test_encryption_decryption_combined() -> Result<(), CryptoCoreError> {
        let mut cs_rng = CsRng::new();
        let key = Key::<KEY_LENGTH>::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes::<8192>();
        let iv = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
        // no additional data
        let encrypted_result = encrypt_combined(&key, &bytes, iv.as_bytes(), None)?;
        assert_ne!(encrypted_result, bytes.to_vec());
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, &encrypted_result, iv.as_bytes(), None)?;
        assert_eq!(bytes.to_vec(), recovered);
        // additional data
        let aad = cs_rng.generate_random_bytes::<42>();
        let encrypted_result = encrypt_combined(&key, &bytes, iv.as_bytes(), Some(&aad))?;
        assert_ne!(encrypted_result, bytes.to_vec());
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, &encrypted_result, iv.as_bytes(), Some(&aad))?;
        assert_eq!(bytes.to_vec(), recovered);
        // data should not be recovered if the AAD is modified
        let aad = cs_rng.generate_random_bytes::<42>();
        let recovered = decrypt_combined(&key, &encrypted_result, iv.as_bytes(), Some(&aad));
        assert_ne!(Ok(bytes.to_vec()), recovered);
        // data should not be recovered if the key is modified
        let new_key = Key::<KEY_LENGTH>::new(&mut cs_rng);
        let recovered = decrypt_combined(&new_key, &encrypted_result, iv.as_bytes(), Some(&aad));
        assert_ne!(Ok(bytes.to_vec()), recovered);
        Ok(())
    }

    #[test]
    fn test_encryption_decryption_detached() -> Result<(), CryptoCoreError> {
        let mut cs_rng = CsRng::new();
        let key = Key::<KEY_LENGTH>::new(&mut cs_rng);
        let bytes = cs_rng.generate_random_bytes::<1024>();
        let iv = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
        // no additional data
        let mut data = bytes;
        let tag = encrypt_in_place_detached(&key, &mut data, iv.as_bytes(), None)?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(&key, &mut data, &tag, iv.as_bytes(), None)?;
        assert_eq!(bytes, data);
        // // additional data
        let ad = cs_rng.generate_random_bytes::<42>();
        let mut data = bytes;
        let tag = encrypt_in_place_detached(&key, &mut data, iv.as_bytes(), Some(&ad))?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(key.as_bytes(), &mut data, &tag, iv.as_bytes(), Some(&ad))?;
        assert_eq!(bytes, data);
        Ok(())
    }

    #[test]
    fn test_dem() -> Result<(), CryptoCoreError> {
        let m = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::new();
        let secret_key = Key::new(&mut rng);
        let c = Aes256GcmCrypto::encrypt(&mut rng, &secret_key, m, additional_data)?;
        let res = Aes256GcmCrypto::decrypt(&secret_key, &c, additional_data)?;
        if res != m {
            return Err(CryptoCoreError::DecryptionError(
                "Decaps failed".to_string(),
            ));
        }
        Ok(())
    }
}
