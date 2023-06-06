//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 256 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use super::dem::AeadExtra;
use crate::{
    symmetric_crypto::{key::SymmetricKey, nonce::Nonce, Dem},
    CryptoCoreError, SecretCBytes,
};
use aead::{
    generic_array::GenericArray,
    stream::{DecryptorBE32, DecryptorLE31, EncryptorBE32, EncryptorLE31},
    Aead, KeyInit, Payload,
};
use aes_gcm::Aes256Gcm as Aes256GcmLib;
use std::{
    fmt::{self, Debug, Formatter},
    ops::Deref,
};

/// Structure implementing `SymmetricCrypto` and the `DEM` interfaces based on
/// AES 256 GCM.
pub struct Aes256Gcm(Aes256GcmLib);

impl Aes256Gcm {
    /// Use a 256-bit AES key.
    pub const KEY_LENGTH: usize = 32;

    /// Use a 96-bit nonce.
    pub const NONCE_LENGTH: usize = 12;

    /// Use a 128-bit MAC tag.
    pub const MAC_LENGTH: usize = 16;

    /// Plaintext size (in bytes) restriction from the NIST
    /// <https://csrc.nist.gov/publications/detail/sp/800-38d/final>
    const MAX_PLAINTEXT_LENGTH: u64 = 68_719_476_704; // (2 ^ 39 - 256) / 8
}

impl Aes256Gcm {
    pub fn new(key: &SymmetricKey<{ Aes256Gcm::KEY_LENGTH }>) -> Self {
        Self(Aes256GcmLib::new(GenericArray::from_slice(key.as_bytes())))
    }

    pub fn into_stream_encryptor_be32(
        self,
        nonce: &Nonce<{ Aes256Gcm::NONCE_LENGTH }>,
    ) -> EncryptorBE32<Aes256GcmLib> {
        EncryptorBE32::from_aead(self.0, nonce.as_bytes().into())
    }

    pub fn into_stream_decryptor_be32(
        self,
        nonce: &Nonce<{ Aes256Gcm::NONCE_LENGTH }>,
    ) -> DecryptorBE32<Aes256GcmLib> {
        DecryptorBE32::from_aead(self.0, nonce.as_bytes().into())
    }

    pub fn into_stream_encryptor_le31(
        self,
        nonce: &Nonce<{ Aes256Gcm::NONCE_LENGTH }>,
    ) -> EncryptorLE31<Aes256GcmLib> {
        EncryptorLE31::from_aead(self.0, nonce.as_bytes().into())
    }

    pub fn into_stream_decryptor_le31(
        self,
        nonce: &Nonce<{ Aes256Gcm::NONCE_LENGTH }>,
    ) -> DecryptorLE31<Aes256GcmLib> {
        DecryptorLE31::from_aead(self.0, nonce.as_bytes().into())
    }
}

impl Deref for Aes256Gcm {
    type Target = Aes256GcmLib;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Aes256Gcm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Aes256Gcm")
    }
}

impl Dem<{ Aes256Gcm::KEY_LENGTH }, { Aes256Gcm::NONCE_LENGTH }, { Aes256Gcm::MAC_LENGTH }>
    for Aes256Gcm
{
    type SymmetricKey = SymmetricKey<{ Aes256Gcm::KEY_LENGTH }>;
    type Nonce = Nonce<{ Aes256Gcm::NONCE_LENGTH }>;

    fn new(symmetric_key: &Self::SymmetricKey) -> Self {
        Self(Aes256GcmLib::new(GenericArray::from_slice(
            symmetric_key.as_bytes(),
        )))
    }

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        if plaintext.len() as u64 > Aes256Gcm::MAX_PLAINTEXT_LENGTH {
            return Err(CryptoCoreError::PlaintextTooBigError {
                plaintext_len: plaintext.len(),
                max: Aes256Gcm::MAX_PLAINTEXT_LENGTH,
            });
        }
        Ok(self
            .0
            .encrypt(
                GenericArray::from_slice(nonce.as_bytes()),
                Payload {
                    msg: plaintext,
                    aad: aad.unwrap_or(b""),
                },
            )
            .map_err(|_| CryptoCoreError::EncryptionError)?)
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        if ciphertext.len() < Self::ENCRYPTION_OVERHEAD {
            return Err(CryptoCoreError::CiphertextTooSmallError {
                ciphertext_len: ciphertext.len(),
                min: Self::ENCRYPTION_OVERHEAD as u64,
            });
        }
        if ciphertext.len() as u64
            > Aes256Gcm::MAX_PLAINTEXT_LENGTH + Self::ENCRYPTION_OVERHEAD as u64
        {
            return Err(CryptoCoreError::CiphertextTooBigError {
                ciphertext_len: ciphertext.len(),
                max: Aes256Gcm::MAX_PLAINTEXT_LENGTH + Self::ENCRYPTION_OVERHEAD as u64,
            });
        }
        // The ciphertext is of the form: nonce || AEAD ciphertext
        Ok(self
            .0
            .decrypt(
                nonce.as_bytes().into(),
                Payload {
                    msg: &ciphertext,
                    aad: aad.unwrap_or(b""),
                },
            )
            .map_err(|_| CryptoCoreError::DecryptionError)?)
    }
}

impl AeadExtra for Aes256Gcm {
    type Algo = Aes256GcmLib;
}

#[cfg(test)]
mod tests {

    use aead::Payload;

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{aes_256_gcm::Aes256Gcm, key::SymmetricKey, nonce::Nonce, Dem},
        CryptoCoreError, CsRng, FixedSizeCBytes, SecretCBytes,
    };

    #[test]
    fn test_dem() -> Result<(), CryptoCoreError> {
        let message = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);

        // Encrypt
        let nonce = Nonce::new(&mut rng);
        let ciphertext = Aes256Gcm::new(&secret_key).encrypt(&nonce, message, additional_data)?;

        // decrypt
        let plaintext =
            Aes256Gcm::new(&secret_key).decrypt(&nonce, &ciphertext, additional_data)?;
        assert_eq!(plaintext, message, "Decryption failed");
        Ok(())
    }

    #[test]
    fn libsodium_compat() {
        let message = b"Hello, World!";

        // the shared secret key
        let mut secret_key_bytes = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];

        // the public nonce
        let mut nonce_bytes = [0u8; libsodium_sys::crypto_aead_aes256gcm_NPUBBYTES as usize];

        //  the cipher text buffer (does not contain the nonce)
        let mut ciphertext: Vec<u8> =
            vec![0; message.len() + libsodium_sys::crypto_aead_aes256gcm_ABYTES as usize];

        // encrypt using libsodium
        let secret_key_ptr = unsafe {
            // initialize the secret key
            let secret_key_ptr: *mut libc::c_uchar =
                secret_key_bytes.as_mut_ptr() as *mut libc::c_uchar;
            libsodium_sys::crypto_aead_aes256gcm_keygen(secret_key_ptr);
            secret_key_ptr
        };

        // encrypt using libsodium
        let mut ciphertext_len: u64 = 0;
        unsafe {
            // generate the nonce
            let nonce_ptr: *mut libc::c_uchar = nonce_bytes.as_mut_ptr() as *mut libc::c_uchar;
            libsodium_sys::randombytes_buf(nonce_ptr as *mut libc::c_void, nonce_bytes.len());

            // now the actual encryption
            let message_ptr: *const libc::c_uchar = message.as_ptr() as *const libc::c_uchar;
            let ciphertext_ptr: *mut libc::c_uchar = ciphertext.as_mut_ptr() as *mut libc::c_uchar;
            let ciphertext_len_ptr: *mut libc::c_ulonglong = &mut ciphertext_len;
            libsodium_sys::crypto_aead_aes256gcm_encrypt(
                ciphertext_ptr,
                ciphertext_len_ptr,
                message_ptr,
                message.len() as libc::c_ulonglong,
                std::ptr::null(),
                0,
                std::ptr::null(),
                nonce_ptr,
                secret_key_ptr,
            );
        }

        // check that the ciphertext has the correct length,
        // the libsodium ciphertext does have a nonce prepended
        assert_eq!(
            ciphertext_len as usize,
            message.len() + Aes256Gcm::MAC_LENGTH,
        );

        // decrypt using salsa_sealbox
        let secret_key =
            SymmetricKey::<{ Aes256Gcm::KEY_LENGTH }>::try_from_bytes(secret_key_bytes).unwrap();
        let plaintext_ = Aes256Gcm::new(&secret_key)
            .decrypt(
                &Nonce::try_from_bytes(nonce_bytes).unwrap(),
                &ciphertext,
                None,
            )
            .unwrap();
        assert!(plaintext_ == message);

        // the other way round

        // encrypt using Aes256Gcm
        let nonce = Nonce::try_from_bytes(nonce_bytes).unwrap();
        let ciphertext = Aes256Gcm::new(&secret_key)
            .encrypt(&nonce, message, None)
            .unwrap();
        assert_eq!(
            ciphertext.len(),
            message.len() + libsodium_sys::crypto_aead_aes256gcm_ABYTES as usize
        );

        // decrypt using libsodium
        //  the plain text buffer (does not contain the nonce)
        let mut plaintext: Vec<u8> =
            vec![0; ciphertext.len() - libsodium_sys::crypto_aead_aes256gcm_ABYTES as usize];
        let mut plaintext_len: u64 = 0;
        unsafe {
            // recover the nonce
            let nonce = nonce.as_bytes();
            let nonce_ptr: *const libc::c_uchar = nonce.as_ptr() as *const libc::c_uchar;

            // recover the ciphertext pointer
            let ciphertext_ptr: *const libc::c_uchar = ciphertext.as_ptr() as *const libc::c_uchar;

            // now the actual decryption
            let plaintext_ptr: *mut libc::c_uchar = plaintext.as_mut_ptr() as *mut libc::c_uchar;
            let plaintext_len_ptr: *mut libc::c_ulonglong = &mut plaintext_len;
            libsodium_sys::crypto_aead_aes256gcm_decrypt(
                plaintext_ptr,
                plaintext_len_ptr,
                std::ptr::null_mut(),
                ciphertext_ptr,
                ciphertext.len() as libc::c_ulonglong,
                std::ptr::null(),
                0,
                nonce_ptr,
                secret_key_ptr,
            );
        }

        // check that the plaintext has the correct length,
        assert_eq!(plaintext_len as usize, message.len());

        // check the plaintext is correct
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_stream() -> Result<(), CryptoCoreError> {
        let message = b"Hello, World!";
        let aad = b"aad";
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let nonce = Nonce::new(&mut rng);

        //
        let mut encryptor = Aes256Gcm::new(&secret_key).into_stream_encryptor_be32(&nonce);
        let mut ciphertext = encryptor.encrypt_next(Payload {
            msg: &message[..6],
            aad,
        })?;
        ciphertext.extend_from_slice(&encryptor.encrypt_next(Payload {
            msg: &message[6..],
            aad,
        })?);

        // decryption
        let mut encryptor = Aes256Gcm::new(&secret_key).into_stream_decryptor_be32(&nonce);
        let mut plaintext = encryptor.decrypt_next(Payload {
            msg: &ciphertext[..4],
            aad,
        })?;
        plaintext.extend_from_slice(&encryptor.decrypt_next(Payload {
            msg: &ciphertext[4..],
            aad,
        })?);

        assert_eq!(
            message.as_slice(),
            plaintext.as_slice(),
            "Decryption failed"
        );
        Ok(())
    }
}
