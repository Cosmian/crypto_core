//! This file exposes the Chacha20 Poly1305 implemented
//! in RustCrypto (https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)

use crate::symmetric_crypto::nonce::NonceTrait;
use crate::{CryptoCoreError, SecretKey};
use chacha20poly1305::ChaCha20Poly1305 as ChaCha20Poly1305Lib;

/// Use a 256-bit AES key.
pub const KEY_LENGTH: usize = 32;

/// Use a 96-bit nonce.
pub const NONCE_LENGTH: usize = 12;

/// Use a 128-bit MAC tag.
pub const MAC_LENGTH: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub struct ChaCha20Poly1305;

use super::AeadExtra;
use super::{key::SymmetricKey, nonce::Nonce, Dem};

impl AeadExtra for ChaCha20Poly1305 {
    type Algo = ChaCha20Poly1305Lib;
}

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
        let nonce = Self::Nonce::new(rng);
        // allocate correct byte number
        let mut res: Vec<u8> = Vec::with_capacity(plaintext.len() + Self::ENCRYPTION_OVERHEAD);
        res.extend_from_slice(nonce.as_bytes());
        res.append(&mut ChaCha20Poly1305::encrypt_combined(
            secret_key.as_bytes(),
            plaintext,
            nonce.as_bytes(),
            aad,
        )?);
        Ok(res)
    }

    fn decrypt(
        secret_key: &Self::SymmetricKey,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, crate::CryptoCoreError> {
        if ciphertext.len() < Self::ENCRYPTION_OVERHEAD {
            return Err(CryptoCoreError::CiphertextTooSmallError {
                ciphertext_len: ciphertext.len(),
                min: Self::ENCRYPTION_OVERHEAD as u64,
            });
        }

        // The ciphertext is of the form: nonce || AEAD ciphertext
        ChaCha20Poly1305::decrypt_combined(
            secret_key.as_bytes(),
            &ciphertext[Self::Nonce::LENGTH..],
            &ciphertext[..Self::Nonce::LENGTH],
            aad,
        )
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{chacha20_poly1305::ChaCha20Poly1305, key::SymmetricKey, Dem},
        CryptoCoreError, CsRng, FixedSizeKey, SecretKey,
    };

    #[test]
    fn test_dem() -> Result<(), CryptoCoreError> {
        let m = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let c = ChaCha20Poly1305::encrypt(&mut rng, &secret_key, m, additional_data)?;
        let res = ChaCha20Poly1305::decrypt(&secret_key, &c, additional_data)?;
        assert_eq!(res, m, "Decryption failed");
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
            ciphertext_len as usize
                + libsodium_sys::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize,
            message.len() + ChaCha20Poly1305::ENCRYPTION_OVERHEAD,
        );

        // prepend the Nonce
        let mut full_ct = nonce_bytes.to_vec();
        full_ct.extend_from_slice(&ciphertext);
        // decrypt using salsa_sealbox
        let secret_key =
            SymmetricKey::<{ ChaCha20Poly1305::KEY_LENGTH }>::try_from_bytes(secret_key_bytes)
                .unwrap();
        let plaintext_ = ChaCha20Poly1305::decrypt(&secret_key, &full_ct, None).unwrap();
        assert!(plaintext_ == message);

        // the other way round

        // encrypt using ChaCha20Poly1305
        let mut rng = CsRng::from_entropy();
        let ciphertext = ChaCha20Poly1305::encrypt(&mut rng, &secret_key, message, None).unwrap();

        // decrypt using libsodium
        //  the plain text buffer (does not contain the nonce)
        let mut plaintext: Vec<u8> =
            vec![
                0;
                ciphertext.len()
                    - libsodium_sys::crypto_aead_chacha20poly1305_IETF_ABYTES as usize
                    - libsodium_sys::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize
            ];
        let mut plaintext_len: u64 = 0;
        unsafe {
            // recover the nonce
            let nonce =
                &ciphertext[..libsodium_sys::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize];
            let nonce_ptr: *const libc::c_uchar = nonce.as_ptr() as *const libc::c_uchar;

            // recover the rest of the ciphertext
            let ciphertext =
                &ciphertext[libsodium_sys::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize..];
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
