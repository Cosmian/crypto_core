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
