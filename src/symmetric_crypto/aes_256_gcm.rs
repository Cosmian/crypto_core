//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 256 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use super::dem::AeadExtra;
use crate::{
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{
        key::SymmetricKey,
        nonce::{Nonce, NonceTrait},
        Dem,
    },
    CryptoCoreError, SecretKey,
};
use aes_gcm::Aes256Gcm as Aes256GcmLib;

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
pub struct Aes256Gcm;

impl Dem<KEY_LENGTH> for Aes256Gcm {
    type SymmetricKey = SymmetricKey<KEY_LENGTH>;
    type Nonce = Nonce<NONCE_LENGTH>;

    const ENCRYPTION_OVERHEAD: usize = Self::Nonce::LENGTH + Self::MAC_LENGTH;
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        secret_key: &Self::SymmetricKey,
        plaintext: &[u8],
        aad: Option<&[u8]>,
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
        res.append(&mut Aes256Gcm::encrypt_combined(
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
        Aes256Gcm::decrypt_combined(
            secret_key.as_bytes(),
            &ciphertext[Self::Nonce::LENGTH..],
            &ciphertext[..Self::Nonce::LENGTH],
            aad,
        )
    }
}

impl AeadExtra for Aes256Gcm {
    type Algo = Aes256GcmLib;
}

#[cfg(test)]
mod tests {

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{
            aes_256_gcm::{self, Aes256Gcm},
            key::SymmetricKey,
            Dem,
        },
        CryptoCoreError, CsRng, FixedSizeKey, SecretKey,
    };

    #[test]
    fn test_dem() -> Result<(), CryptoCoreError> {
        let m = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let c = Aes256Gcm::encrypt(&mut rng, &secret_key, m, additional_data)?;
        let res = Aes256Gcm::decrypt(&secret_key, &c, additional_data)?;
        assert_eq!(res, m, "Decryption failed");
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
            ciphertext_len as usize + aes_256_gcm::NONCE_LENGTH,
            message.len() + Aes256Gcm::ENCRYPTION_OVERHEAD,
        );

        // prepend the Nonce
        let mut full_ct = nonce_bytes.to_vec();
        full_ct.extend_from_slice(&ciphertext);
        // decrypt using salsa_sealbox
        let secret_key =
            SymmetricKey::<{ Aes256Gcm::KEY_LENGTH }>::try_from_bytes(secret_key_bytes).unwrap();
        let plaintext_ = Aes256Gcm::decrypt(&secret_key, &full_ct, None).unwrap();
        assert!(plaintext_ == message);

        // the other way round

        // encrypt using Aes256Gcm
        let mut rng = CsRng::from_entropy();
        let ciphertext = Aes256Gcm::encrypt(&mut rng, &secret_key, message, None).unwrap();

        // decrypt using libsodium
        //  the plain text buffer (does not contain the nonce)
        let mut plaintext: Vec<u8> = vec![
            0;
            ciphertext.len()
                - libsodium_sys::crypto_aead_aes256gcm_ABYTES as usize
                - libsodium_sys::crypto_aead_aes256gcm_NPUBBYTES
                    as usize
        ];
        let mut plaintext_len: u64 = 0;
        unsafe {
            // recover the nonce
            let nonce = &ciphertext[..libsodium_sys::crypto_aead_aes256gcm_NPUBBYTES as usize];
            let nonce_ptr: *const libc::c_uchar = nonce.as_ptr() as *const libc::c_uchar;

            // recover the rest of the ciphertext
            let ciphertext = &ciphertext[libsodium_sys::crypto_aead_aes256gcm_NPUBBYTES as usize..];
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
        assert_eq!(plaintext_len as usize, message.len(),);

        // check the plaintext is correct
        assert_eq!(plaintext, message);
    }
}
