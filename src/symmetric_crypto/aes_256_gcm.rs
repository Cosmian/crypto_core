//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 256 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use std::{
    fmt::{self, Debug, Formatter},
    ops::Deref,
};

use aead::{generic_array::GenericArray, KeyInit};
use aes_gcm::Aes256Gcm as Aes256GcmLib;

use super::dem::{DemInPlace, DemStream, Instantiable};
use crate::{
    symmetric_crypto::{key::SymmetricKey, nonce::Nonce, Dem},
    RandomFixedSizeCBytes,
};

/// Structure implementing `SymmetricCrypto` and the `DEM` interfaces based on
/// AES 256 GCM.
#[derive(Clone)]
pub struct Aes256Gcm(Aes256GcmLib);

impl Aes256Gcm {
    /// Use a 256-bit AES key.
    pub const KEY_LENGTH: usize = 32;
    /// Use a 128-bit MAC tag.
    pub const MAC_LENGTH: usize = 16;
    /// Plaintext size (in bytes) restriction from the NIST
    /// <https://csrc.nist.gov/publications/detail/sp/800-38d/final>
    // (2 ^ 39 - 256) / 8
    pub const MAX_PLAINTEXT_LENGTH: u64 = 68_719_476_704;
    /// Use a 96-bit nonce.
    pub const NONCE_LENGTH: usize = 12;
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

impl Instantiable<{ Self::KEY_LENGTH }> for Aes256Gcm {
    type Secret = SymmetricKey<{ Self::KEY_LENGTH }>;

    fn new(symmetric_key: &Self::Secret) -> Self {
        Self(Aes256GcmLib::new(GenericArray::from_slice(
            symmetric_key.as_bytes(),
        )))
    }
}

impl Dem<{ Self::KEY_LENGTH }, { Self::NONCE_LENGTH }, { Self::MAC_LENGTH }, Aes256GcmLib>
    for Aes256Gcm
{
    type Nonce = Nonce<{ Self::NONCE_LENGTH }>;
}

impl DemInPlace<{ Self::KEY_LENGTH }, { Self::NONCE_LENGTH }, { Self::MAC_LENGTH }, Aes256GcmLib>
    for Aes256Gcm
{
    type Nonce = Nonce<{ Self::NONCE_LENGTH }>;
}

impl DemStream<{ Self::KEY_LENGTH }, { Self::NONCE_LENGTH }, { Self::MAC_LENGTH }, Aes256GcmLib>
    for Aes256Gcm
{
    type Nonce = Nonce<{ Self::NONCE_LENGTH }>;

    fn into_aead_stream_backend(self) -> Aes256GcmLib {
        self.0
    }
}

#[cfg(test)]
mod tests {

    use aead::Payload;

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{
            aes_256_gcm::Aes256Gcm, dem::DemStream, key::SymmetricKey, nonce::Nonce, Dem,
            DemInPlace, Instantiable,
        },
        CryptoCoreError, CsRng, FixedSizeCBytes, RandomFixedSizeCBytes,
    };

    #[test]
    fn test_dem_combined() -> Result<(), CryptoCoreError> {
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
    fn test_dem_in_place() -> Result<(), CryptoCoreError> {
        let message = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let nonce = Nonce::new(&mut rng);

        // the in-place buffer
        let mut buffer = message.to_vec();

        // Encrypt
        let tag = Aes256Gcm::new(&secret_key).encrypt_in_place_detached(
            &nonce,
            &mut buffer,
            additional_data,
        )?;

        // decrypt
        Aes256Gcm::new(&secret_key).decrypt_in_place_detached(
            &nonce,
            &mut buffer,
            &tag,
            additional_data,
        )?;
        assert_eq!(&message[..], buffer.as_slice(), "Decryption failed");
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
            let secret_key_ptr: *mut libc::c_uchar = secret_key_bytes.as_mut_ptr().cast::<u8>();
            libsodium_sys::crypto_aead_aes256gcm_keygen(secret_key_ptr);
            secret_key_ptr
        };

        // encrypt using libsodium
        let mut ciphertext_len: u64 = 0;
        unsafe {
            // generate the nonce
            let nonce_ptr: *mut libc::c_uchar = nonce_bytes.as_mut_ptr().cast::<u8>();
            libsodium_sys::randombytes_buf(nonce_ptr.cast::<libc::c_void>(), nonce_bytes.len());

            // now the actual encryption
            let message_ptr: *const libc::c_uchar = message.as_ptr().cast::<u8>();
            let ciphertext_ptr: *mut libc::c_uchar = ciphertext.as_mut_ptr().cast::<u8>();
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
            let nonce_ptr: *const libc::c_uchar = nonce.as_ptr().cast::<u8>();

            // recover the ciphertext pointer
            let ciphertext_ptr: *const libc::c_uchar = ciphertext.as_ptr().cast::<u8>();

            // now the actual decryption
            let plaintext_ptr: *mut libc::c_uchar = plaintext.as_mut_ptr().cast::<u8>();
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
    fn test_stream_be32() -> Result<(), CryptoCoreError> {
        let message = b"Hello, World!";
        let aad = b"the aad";
        // there will be 2 chunks for the message, one of size 8 and one of size 5
        const BLOCK_SIZE: usize = 8;

        // generate a random key and nonce
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let nonce = Nonce::new(&mut rng);

        // Instantiate an encryptor
        let mut encryptor = Aes256Gcm::new(&secret_key).into_stream_encryptor_be32(&nonce);

        // encrypt the first chunk
        let mut ciphertext = encryptor.encrypt_next(Payload {
            msg: &message[..BLOCK_SIZE],
            aad,
        })?;

        // encrypt the second and last chunk
        ciphertext.extend_from_slice(&encryptor.encrypt_last(Payload {
            msg: &message[BLOCK_SIZE..],
            aad,
        })?);

        // decryption

        // Instantiate a decryptor
        let mut decryptor = Aes256Gcm::new(&secret_key).into_stream_decryptor_be32(&nonce);

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[..BLOCK_SIZE + Aes256Gcm::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[BLOCK_SIZE + Aes256Gcm::MAC_LENGTH..],
            aad,
        })?);

        assert_eq!(
            message.as_slice(),
            plaintext.as_slice(),
            "Decryption failed"
        );
        Ok(())
    }

    #[test]
    fn test_stream_le31() -> Result<(), CryptoCoreError> {
        let message = b"Hello, World!";
        let aad = b"the aad";
        // there will be 2 chunks for the message, one of size 8 and one of size 5
        const BLOCK_SIZE: usize = 8;

        // generate a random key and nonce
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let nonce = Nonce::new(&mut rng);

        // Instantiate an encryptor
        let mut encryptor = Aes256Gcm::new(&secret_key).into_stream_encryptor_le31(&nonce);

        // encrypt the first chunk
        let mut ciphertext = encryptor.encrypt_next(Payload {
            msg: &message[..BLOCK_SIZE],
            aad,
        })?;

        // encrypt the second and last chunk
        ciphertext.extend_from_slice(&encryptor.encrypt_last(Payload {
            msg: &message[BLOCK_SIZE..],
            aad,
        })?);

        // decryption

        // Instantiate a decryptor
        let mut decryptor = Aes256Gcm::new(&secret_key).into_stream_decryptor_le31(&nonce);

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[..BLOCK_SIZE + Aes256Gcm::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[BLOCK_SIZE + Aes256Gcm::MAC_LENGTH..],
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
