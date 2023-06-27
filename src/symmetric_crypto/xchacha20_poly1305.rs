//! This file exposes the `XChacha20` Poly1305 implemented
//! in `RustCrypto` `<https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305>`.
use std::{fmt::Debug, ops::Deref};

use aead::{generic_array::GenericArray, KeyInit};
use chacha20poly1305::XChaCha20Poly1305 as XChaCha20Poly1305Lib;

use super::{
    dem::{DemStream, Instantiable},
    key::SymmetricKey,
    nonce::Nonce,
    Dem, DemInPlace,
};
use crate::RandomFixedSizeCBytes;

pub struct XChaCha20Poly1305(XChaCha20Poly1305Lib);

impl XChaCha20Poly1305 {
    /// Use a 256-bit key.
    pub const KEY_LENGTH: usize = 32;
    /// Use a 128-bit MAC tag.
    pub const MAC_LENGTH: usize = 16;
    /// Use a 192-bit nonce.
    pub const NONCE_LENGTH: usize = 24;
    pub const ENCRYPTION_OVERHEAD: usize = Self::MAC_LENGTH + Self::NONCE_LENGTH;
}

impl Deref for XChaCha20Poly1305 {
    type Target = XChaCha20Poly1305Lib;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for XChaCha20Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XChaCha20Poly1305").finish()
    }
}

impl Instantiable<{ Self::KEY_LENGTH }> for XChaCha20Poly1305 {
    type Secret = SymmetricKey<{ Self::KEY_LENGTH }>;

    fn new(symmetric_key: &Self::Secret) -> Self {
        Self(XChaCha20Poly1305Lib::new(GenericArray::from_slice(
            symmetric_key.as_bytes(),
        )))
    }
}

impl Dem<{ Self::KEY_LENGTH }, { Self::NONCE_LENGTH }, { Self::MAC_LENGTH }, XChaCha20Poly1305Lib>
    for XChaCha20Poly1305
{
    type Nonce = Nonce<{ Self::NONCE_LENGTH }>;
}

impl
    DemInPlace<
        { Self::KEY_LENGTH },
        { Self::NONCE_LENGTH },
        { Self::MAC_LENGTH },
        XChaCha20Poly1305Lib,
    > for XChaCha20Poly1305
{
    type Nonce = Nonce<{ Self::NONCE_LENGTH }>;
}

impl
    DemStream<
        { Self::KEY_LENGTH },
        { Self::NONCE_LENGTH },
        { Self::MAC_LENGTH },
        XChaCha20Poly1305Lib,
    > for XChaCha20Poly1305
{
    type Nonce = Nonce<{ Self::NONCE_LENGTH }>;

    fn into_aead_stream_backend(self) -> XChaCha20Poly1305Lib {
        self.0
    }
}

#[cfg(test)]
mod tests {

    use aead::Payload;

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{
            dem::{DemStream, Instantiable},
            key::SymmetricKey,
            nonce::Nonce,
            xchacha20_poly1305::XChaCha20Poly1305,
            Dem, DemInPlace,
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
        let ciphertext =
            XChaCha20Poly1305::new(&secret_key).encrypt(&nonce, message, additional_data)?;

        // decrypt
        let plaintext =
            XChaCha20Poly1305::new(&secret_key).decrypt(&nonce, &ciphertext, additional_data)?;
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
        let tag = XChaCha20Poly1305::new(&secret_key).encrypt_in_place_detached(
            &nonce,
            &mut buffer,
            additional_data,
        )?;

        // decrypt
        XChaCha20Poly1305::new(&secret_key).decrypt_in_place_detached(
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
        let mut secret_key_bytes =
            [0u8; libsodium_sys::crypto_aead_xchacha20poly1305_IETF_KEYBYTES as usize];

        // the public nonce
        let mut nonce_bytes =
            [0u8; libsodium_sys::crypto_aead_xchacha20poly1305_IETF_NPUBBYTES as usize];

        //  the cipher text buffer (does not contain the nonce)
        let mut ciphertext: Vec<u8> =
            vec![
                0;
                message.len() + libsodium_sys::crypto_aead_xchacha20poly1305_IETF_ABYTES as usize
            ];

        // encrypt using libsodium
        let secret_key_ptr = unsafe {
            // initialize the secret key
            let secret_key_ptr: *mut libc::c_uchar = secret_key_bytes.as_mut_ptr().cast::<u8>();
            libsodium_sys::crypto_aead_xchacha20poly1305_ietf_keygen(secret_key_ptr);
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
            libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
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
            message.len() + XChaCha20Poly1305::MAC_LENGTH,
        );

        // prepend the Nonce

        // decrypt using salsa_sealbox
        let secret_key =
            SymmetricKey::<{ XChaCha20Poly1305::KEY_LENGTH }>::try_from_bytes(secret_key_bytes)
                .unwrap();
        let plaintext_ = XChaCha20Poly1305::new(&secret_key)
            .decrypt(
                &Nonce::try_from_bytes(nonce_bytes).unwrap(),
                &ciphertext,
                None,
            )
            .unwrap();
        assert!(plaintext_ == message);

        // the other way round

        // encrypt using XChaCha20Poly1305
        let nonce = Nonce::try_from_bytes(nonce_bytes).unwrap();
        let ciphertext = XChaCha20Poly1305::new(&secret_key)
            .encrypt(&nonce, message, None)
            .unwrap();

        // decrypt using libsodium
        //  the plain text buffer (does not contain the nonce)
        let mut plaintext: Vec<u8> = vec![
            0;
            ciphertext.len()
                - libsodium_sys::crypto_aead_xchacha20poly1305_IETF_ABYTES
                    as usize
        ];
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
            libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
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
        assert_eq!(plaintext_len as usize, message.len(),);

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
        let mut encryptor = XChaCha20Poly1305::new(&secret_key).into_stream_encryptor_be32(&nonce);

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
        let mut decryptor = XChaCha20Poly1305::new(&secret_key).into_stream_decryptor_be32(&nonce);

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[..BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH..],
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
        let mut encryptor = XChaCha20Poly1305::new(&secret_key).into_stream_encryptor_le31(&nonce);

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
        let mut decryptor = XChaCha20Poly1305::new(&secret_key).into_stream_decryptor_le31(&nonce);

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[..BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH..],
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
