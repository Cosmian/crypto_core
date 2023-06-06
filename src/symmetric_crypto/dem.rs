use core::fmt::Debug;
use std::vec::Vec;

use aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload};

use crate::{CryptoCoreError, FixedSizeCBytes, SecretCBytes};

/// Defines a DEM based on a symmetric scheme as defined in section 9.1 of the
/// [ISO 2004](https://www.shoup.net/iso/std6.pdf).
pub trait Dem<const KEY_LENGTH: usize, const NONCE_LENGTH: usize, const MAC_LENGTH: usize>:
    Debug
{
    /// Number of bytes added to the message length in the encapsulation.
    const ENCRYPTION_OVERHEAD: usize = NONCE_LENGTH + MAC_LENGTH;

    type SymmetricKey: SecretCBytes<KEY_LENGTH>;
    type Nonce: FixedSizeCBytes<NONCE_LENGTH>;

    /// Instantiate the DEM
    fn new(symmetric_key: &Self::SymmetricKey) -> Self;

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
    ) -> Result<Vec<u8>, CryptoCoreError>;

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
    ) -> Result<Vec<u8>, CryptoCoreError>;
}

pub trait AeadExtra {
    type Algo: AeadInPlace + Aead + KeyInit;

    /// Encrypts a message using a secret key and a public nonce in combined mode:
    /// the encrypted message, as well as a tag authenticating both the confidential
    /// message and non-confidential data, are put into the encrypted result.
    ///
    /// The total length of the encrypted data is the message length + `MAC_LENGTH`
    fn encrypt_combined(
        key: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        Self::Algo::new(GenericArray::from_slice(key))
            .encrypt(
                GenericArray::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.unwrap_or_default(),
                },
            )
            .map_err(|_| CryptoCoreError::EncryptionError)
    }

    /// Decrypts a message in combined mode: the MAC is appended to the cipher text
    ///
    /// The provided additional data must match those provided during encryption for
    /// the MAC to verify.
    ///
    /// Decryption will never be performed, even partially, before verification.
    fn decrypt_combined(
        key: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        Self::Algo::new(GenericArray::from_slice(key))
            .decrypt(
                GenericArray::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: aad.unwrap_or_default(),
                },
            )
            .map_err(|_| CryptoCoreError::DecryptionError)
    }

    /// Encrypts a message in place using a secret key and a public nonce in
    /// detached mode: the tag authenticating both the confidential
    /// message and non-confidential data, are returned separately
    ///
    /// The tag length is `MAC_LENGTH`
    fn encrypt_in_place_detached(
        key: &[u8],
        bytes: &mut [u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(nonce);
        Self::Algo::new(key)
            .encrypt_in_place_detached(nonce, aad.unwrap_or_default(), bytes)
            .map_err(|_| CryptoCoreError::DecryptionError)
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
        key: &[u8],
        bytes: &mut [u8],
        tag: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(), CryptoCoreError> {
        Self::Algo::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                aad.unwrap_or_default(),
                bytes,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| CryptoCoreError::DecryptionError)
    }
}

// #[cfg(test)]
// mod tests {

//     use crate::{
//         reexport::rand_core::{RngCore, SeedableRng},
//         symmetric_crypto::{
//             aes_128_gcm::Aes128Gcm, aes_256_gcm::Aes256Gcm, chacha20_poly1305::ChaCha20Poly1305,
//             dem::AeadExtra, key::SymmetricKey, nonce::Nonce,
//         },
//         CryptoCoreError, CsRng, SecretCBytes,
//     };

//     #[test]
//     fn test_encryption_decryption_combined_aes_256_gcm() -> Result<(), CryptoCoreError> {
//         test_encryption_decryption_combined::<Aes256Gcm>()
//     }
//     #[test]
//     fn test_encryption_decryption_combined_aes_128_gcm() -> Result<(), CryptoCoreError> {
//         test_encryption_decryption_combined::<Aes128Gcm>()
//     }
//     #[test]
//     fn test_encryption_decryption_combined_chacha20_poly1305() -> Result<(), CryptoCoreError> {
//         test_encryption_decryption_combined::<ChaCha20Poly1305>()
//     }

//     fn test_encryption_decryption_combined<T>() -> Result<(), CryptoCoreError>
//     where
//         T: AeadExtra,
//     {
//         let mut cs_rng = CsRng::from_entropy();
//         let key = SymmetricKey::<KEY_LENGTH>::new(&mut cs_rng);
//         let mut bytes = [0; 8192];
//         cs_rng.fill_bytes(&mut bytes);
//         let iv = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
//         // no additional data
//         let encrypted_result = Aes256Gcm::encrypt_combined(&key, &bytes, iv.as_bytes(), None)?;
//         assert_ne!(encrypted_result, bytes.to_vec());
//         assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
//         let recovered = Aes256Gcm::decrypt_combined(&key, &encrypted_result, iv.as_bytes(), None)?;
//         assert_eq!(bytes.to_vec(), recovered);
//         // additional data
//         let mut aad = [0; 42];
//         cs_rng.fill_bytes(&mut aad);
//         let encrypted_result =
//             Aes256Gcm::encrypt_combined(&key, &bytes, iv.as_bytes(), Some(&aad))?;
//         assert_ne!(encrypted_result, bytes.to_vec());
//         assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
//         let recovered =
//             Aes256Gcm::decrypt_combined(&key, &encrypted_result, iv.as_bytes(), Some(&aad))?;
//         assert_eq!(bytes.to_vec(), recovered);
//         // data should not be recovered if the AAD is modified
//         let mut aad = [0; 42];
//         cs_rng.fill_bytes(&mut aad);
//         let recovered =
//             Aes256Gcm::decrypt_combined(&key, &encrypted_result, iv.as_bytes(), Some(&aad));
//         assert!(matches!(recovered, Err(CryptoCoreError::DecryptionError)));
//         // data should not be recovered if the key is modified
//         let new_key = SymmetricKey::<KEY_LENGTH>::new(&mut cs_rng);
//         let recovered =
//             Aes256Gcm::decrypt_combined(&new_key, &encrypted_result, iv.as_bytes(), Some(&aad));
//         assert!(matches!(recovered, Err(CryptoCoreError::DecryptionError)));
//         Ok(())
//     }

//     #[test]
//     fn test_encryption_decryption_detached_aes_128_gcm() -> Result<(), CryptoCoreError> {
//         test_encryption_decryption_detached::<Aes128Gcm>()
//     }
//     #[test]
//     fn test_encryption_decryption_detached_aes_256_gcm() -> Result<(), CryptoCoreError> {
//         test_encryption_decryption_detached::<Aes256Gcm>()
//     }
//     #[test]
//     fn test_encryption_decryption_detached_chacha20_poly1306() -> Result<(), CryptoCoreError> {
//         test_encryption_decryption_detached::<ChaCha20Poly1305>()
//     }

//     fn test_encryption_decryption_detached<T>() -> Result<(), CryptoCoreError>
//     where
//         T: AeadExtra,
//     {
//         let mut cs_rng = CsRng::from_entropy();
//         let key = SymmetricKey::<KEY_LENGTH>::new(&mut cs_rng);
//         let mut bytes = [0; 1024];
//         cs_rng.fill_bytes(&mut bytes);
//         let iv = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
//         // no additional data
//         let mut data = bytes;
//         let tag = Aes256Gcm::encrypt_in_place_detached(&key, &mut data, iv.as_bytes(), None)?;
//         assert_ne!(bytes, data);
//         assert_eq!(bytes.len(), data.len());
//         assert_eq!(MAC_LENGTH, tag.len());
//         Aes256Gcm::decrypt_in_place_detached(&key, &mut data, &tag, iv.as_bytes(), None)?;
//         assert_eq!(bytes, data);
//         // // additional data
//         let mut ad = [0; 42];
//         cs_rng.fill_bytes(&mut ad);
//         let mut data = bytes;
//         let tag = Aes256Gcm::encrypt_in_place_detached(&key, &mut data, iv.as_bytes(), Some(&ad))?;
//         assert_ne!(bytes, data);
//         assert_eq!(bytes.len(), data.len());
//         assert_eq!(MAC_LENGTH, tag.len());
//         Aes256Gcm::decrypt_in_place_detached(
//             key.as_bytes(),
//             &mut data,
//             &tag,
//             iv.as_bytes(),
//             Some(&ad),
//         )?;
//         assert_eq!(bytes, data);
//         Ok(())
//     }
// }
