//! This file exposes the Chacha20 Poly1305 implemented
//! in RustCrypto (https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)
use super::dem::Instantiable;
use super::DemInPlace;
use super::{key::SymmetricKey, nonce::Nonce, Dem};
use crate::RandomFixedSizeCBytes;
use aead::{generic_array::GenericArray, KeyInit};
use chacha20poly1305::ChaCha20Poly1305 as ChaCha20Poly1305Lib;
use std::fmt::Debug;

pub struct ChaCha20Poly1305(ChaCha20Poly1305Lib);

impl ChaCha20Poly1305 {
    /// Use a 256-bit key.
    pub const KEY_LENGTH: usize = 32;

    /// Use a 96-bit nonce.
    pub const NONCE_LENGTH: usize = 12;

    /// Use a 128-bit MAC tag.
    pub const MAC_LENGTH: usize = 16;
}

impl Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305").finish()
    }
}

impl Instantiable<{ ChaCha20Poly1305::KEY_LENGTH }> for ChaCha20Poly1305 {
    type Secret = SymmetricKey<{ ChaCha20Poly1305::KEY_LENGTH }>;

    fn new(symmetric_key: &Self::Secret) -> Self {
        Self(ChaCha20Poly1305Lib::new(GenericArray::from_slice(
            symmetric_key.as_bytes(),
        )))
    }
}

impl
    Dem<
        { ChaCha20Poly1305::KEY_LENGTH },
        { ChaCha20Poly1305::NONCE_LENGTH },
        { ChaCha20Poly1305::MAC_LENGTH },
    > for ChaCha20Poly1305
{
    type AeadAlgo = ChaCha20Poly1305Lib;
    type Nonce = Nonce<{ ChaCha20Poly1305::NONCE_LENGTH }>;

    fn aead_backend<'a>(&'a self) -> &'a Self::AeadAlgo {
        &self.0
    }
}

impl
    DemInPlace<
        { ChaCha20Poly1305::KEY_LENGTH },
        { ChaCha20Poly1305::NONCE_LENGTH },
        { ChaCha20Poly1305::MAC_LENGTH },
    > for ChaCha20Poly1305
{
    type AeadInPlaceAlgo = ChaCha20Poly1305Lib;
    type Nonce = Nonce<{ ChaCha20Poly1305::NONCE_LENGTH }>;

    fn aead_in_place_backend<'a>(&'a self) -> &'a Self::AeadInPlaceAlgo {
        &self.0
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{
            chacha20_poly1305::ChaCha20Poly1305, dem::Instantiable, key::SymmetricKey,
            nonce::Nonce, Dem,
        },
        CryptoCoreError, CsRng, FixedSizeCBytes, RandomFixedSizeCBytes,
    };

    #[test]
    fn test_dem() -> Result<(), CryptoCoreError> {
        let message = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);

        // Encrypt
        let nonce = Nonce::new(&mut rng);
        let ciphertext =
            ChaCha20Poly1305::new(&secret_key).encrypt(&nonce, message, additional_data)?;

        // decrypt
        let plaintext =
            ChaCha20Poly1305::new(&secret_key).decrypt(&nonce, &ciphertext, additional_data)?;
        assert_eq!(plaintext, message, "Decryption failed");
        Ok(())
    }

    #[test]
    fn libsodium_compat() {
        let message = b"Hello, World!";

        // the shared secret key
        let mut secret_key_bytes =
            [0u8; libsodium_sys::crypto_aead_chacha20poly1305_IETF_KEYBYTES as usize];

        // the public nonce
        let mut nonce_bytes =
            [0u8; libsodium_sys::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize];

        //  the cipher text buffer (does not contain the nonce)
        let mut ciphertext: Vec<u8> =
            vec![
                0;
                message.len() + libsodium_sys::crypto_aead_chacha20poly1305_IETF_ABYTES as usize
            ];

        // encrypt using libsodium
        let secret_key_ptr = unsafe {
            // initialize the secret key
            let secret_key_ptr: *mut libc::c_uchar =
                secret_key_bytes.as_mut_ptr() as *mut libc::c_uchar;
            libsodium_sys::crypto_aead_chacha20poly1305_ietf_keygen(secret_key_ptr);
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
            libsodium_sys::crypto_aead_chacha20poly1305_ietf_encrypt(
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
            message.len() + ChaCha20Poly1305::MAC_LENGTH,
        );

        // prepend the Nonce

        // decrypt using salsa_sealbox
        let secret_key =
            SymmetricKey::<{ ChaCha20Poly1305::KEY_LENGTH }>::try_from_bytes(secret_key_bytes)
                .unwrap();
        let plaintext_ = ChaCha20Poly1305::new(&secret_key)
            .decrypt(
                &Nonce::try_from_bytes(nonce_bytes).unwrap(),
                &ciphertext,
                None,
            )
            .unwrap();
        assert!(plaintext_ == message);

        // the other way round

        // encrypt using ChaCha20Poly1305
        let nonce = Nonce::try_from_bytes(nonce_bytes).unwrap();
        let ciphertext = ChaCha20Poly1305::new(&secret_key)
            .encrypt(&nonce, message, None)
            .unwrap();

        // decrypt using libsodium
        //  the plain text buffer (does not contain the nonce)
        let mut plaintext: Vec<u8> =
            vec![
                0;
                ciphertext.len() - libsodium_sys::crypto_aead_chacha20poly1305_IETF_ABYTES as usize
            ];
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
            libsodium_sys::crypto_aead_chacha20poly1305_ietf_decrypt(
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
}
