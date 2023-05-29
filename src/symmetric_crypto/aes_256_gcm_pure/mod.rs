//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 256 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use aes_gcm::{
    aead::{Aead, Payload},
    aes::cipher::generic_array::GenericArray,
    AeadInPlace, Aes256Gcm, KeyInit,
};

use crate::{
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{
        key::SymmetricKey,
        nonce::{Nonce, NonceTrait},
        Dem,
    },
    CryptoCoreError, SecretKey,
};

/// Use a 256-bit AES key.
pub const KEY_LENGTH: usize = 32;

/// Use a 96-bit nonce.
pub const NONCE_LENGTH: usize = 12;

/// Use a 128-bit MAC tag.
pub const MAC_LENGTH: usize = 16;

/// Plaintext size (in bytes) restriction from the NIST
/// <https://csrc.nist.gov/publications/detail/sp/800-38d/final>
const MAX_PLAINTEXT_LENGTH: u64 = 68_719_476_704; // (2 ^ 39 - 256) / 8

/// Structure implementing `SymmetricCrypto` and the `DEM` interfaces based on
/// AES 256 GCM.
#[derive(Debug, PartialEq, Eq)]
pub struct Aes256GcmCrypto;

impl Dem<KEY_LENGTH> for Aes256GcmCrypto {
    type SymmetricKey = SymmetricKey<KEY_LENGTH>;
    type Nonce = Nonce<NONCE_LENGTH>;

    const ENCRYPTION_OVERHEAD: usize = Self::Nonce::LENGTH + Self::MAC_LENGTH;
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        secret_key: &Self::SymmetricKey,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        if plaintext.len() as u64 > MAX_PLAINTEXT_LENGTH {
            return Err(CryptoCoreError::PlaintextTooBigError {
                plaintext_len: plaintext.len(),
                max: MAX_PLAINTEXT_LENGTH,
            });
        }
        let nonce = Self::Nonce::new(rng);
        // allocate correct byte number
        let mut res: Vec<u8> = Vec::with_capacity(plaintext.len() + Self::ENCRYPTION_OVERHEAD);
        res.extend_from_slice(nonce.as_bytes());
        res.append(&mut encrypt_combined(
            secret_key.as_slice(),
            plaintext,
            nonce.as_bytes(),
            additional_data,
        )?);
        Ok(res)
    }

    fn decrypt(
        secret_key: &Self::SymmetricKey,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        if ciphertext.len() < Self::ENCRYPTION_OVERHEAD {
            return Err(CryptoCoreError::CiphertextTooSmallError {
                ciphertext_len: ciphertext.len(),
                min: Self::ENCRYPTION_OVERHEAD as u64,
            });
        }
        if ciphertext.len() as u64 > MAX_PLAINTEXT_LENGTH + Self::ENCRYPTION_OVERHEAD as u64 {
            return Err(CryptoCoreError::CiphertextTooBigError {
                ciphertext_len: ciphertext.len(),
                max: MAX_PLAINTEXT_LENGTH + Self::ENCRYPTION_OVERHEAD as u64,
            });
        }
        // The ciphertext is of the form: nonce || AEAD ciphertext
        decrypt_combined(
            secret_key.as_slice(),
            &ciphertext[Self::Nonce::LENGTH..],
            &ciphertext[..Self::Nonce::LENGTH],
            additional_data,
        )
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
    Aes256Gcm::new(GenericArray::from_slice(key))
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
    Aes256Gcm::new(GenericArray::from_slice(key))
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
    Aes256Gcm::new(GenericArray::from_slice(key))
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            additional_data.unwrap_or_default(),
            bytes,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| CryptoCoreError::DecryptionError)
}

#[cfg(test)]
mod tests {

    use crate::{
        reexport::rand_core::{RngCore, SeedableRng},
        symmetric_crypto::{
            aes_256_gcm_pure::{
                decrypt_combined, decrypt_in_place_detached, encrypt_combined,
                encrypt_in_place_detached, Aes256GcmCrypto, Nonce, KEY_LENGTH, MAC_LENGTH,
                NONCE_LENGTH,
            },
            key::SymmetricKey,
            nonce::NonceTrait,
            Dem,
        },
        CryptoCoreError, CsRng, SecretKey,
    };

    #[test]
    fn test_encryption_decryption_combined() -> Result<(), CryptoCoreError> {
        let mut cs_rng = CsRng::from_entropy();
        let key = SymmetricKey::<KEY_LENGTH>::new(&mut cs_rng);
        let mut bytes = [0; 8192];
        cs_rng.fill_bytes(&mut bytes);
        let iv = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
        // no additional data
        let encrypted_result = encrypt_combined(&key, &bytes, iv.as_bytes(), None)?;
        assert_ne!(encrypted_result, bytes.to_vec());
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, &encrypted_result, iv.as_bytes(), None)?;
        assert_eq!(bytes.to_vec(), recovered);
        // additional data
        let mut aad = [0; 42];
        cs_rng.fill_bytes(&mut aad);
        let encrypted_result = encrypt_combined(&key, &bytes, iv.as_bytes(), Some(&aad))?;
        assert_ne!(encrypted_result, bytes.to_vec());
        assert_eq!(bytes.len() + MAC_LENGTH, encrypted_result.len());
        let recovered = decrypt_combined(&key, &encrypted_result, iv.as_bytes(), Some(&aad))?;
        assert_eq!(bytes.to_vec(), recovered);
        // data should not be recovered if the AAD is modified
        let mut aad = [0; 42];
        cs_rng.fill_bytes(&mut aad);
        let recovered = decrypt_combined(&key, &encrypted_result, iv.as_bytes(), Some(&aad));
        assert!(matches!(recovered, Err(CryptoCoreError::DecryptionError)));
        // data should not be recovered if the key is modified
        let new_key = SymmetricKey::<KEY_LENGTH>::new(&mut cs_rng);
        let recovered = decrypt_combined(&new_key, &encrypted_result, iv.as_bytes(), Some(&aad));
        assert!(matches!(recovered, Err(CryptoCoreError::DecryptionError)));
        Ok(())
    }

    #[test]
    fn test_encryption_decryption_detached() -> Result<(), CryptoCoreError> {
        let mut cs_rng = CsRng::from_entropy();
        let key = SymmetricKey::<KEY_LENGTH>::new(&mut cs_rng);
        let mut bytes = [0; 1024];
        cs_rng.fill_bytes(&mut bytes);
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
        let mut ad = [0; 42];
        cs_rng.fill_bytes(&mut ad);
        let mut data = bytes;
        let tag = encrypt_in_place_detached(&key, &mut data, iv.as_bytes(), Some(&ad))?;
        assert_ne!(bytes, data);
        assert_eq!(bytes.len(), data.len());
        assert_eq!(MAC_LENGTH, tag.len());
        decrypt_in_place_detached(key.as_slice(), &mut data, &tag, iv.as_bytes(), Some(&ad))?;
        assert_eq!(bytes, data);
        Ok(())
    }

    #[test]
    fn test_dem() -> Result<(), CryptoCoreError> {
        let m = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let c = Aes256GcmCrypto::encrypt(&mut rng, &secret_key, m, additional_data)?;
        let res = Aes256GcmCrypto::decrypt(&secret_key, &c, additional_data)?;
        assert_eq!(res, m, "Decryption failed");
        Ok(())
    }
}
