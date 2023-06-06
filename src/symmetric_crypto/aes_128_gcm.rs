//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 128 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use super::{dem::AeadExtra, nonce::Nonce};
use crate::{
    symmetric_crypto::{key::SymmetricKey, Dem},
    CryptoCoreError, SecretCBytes,
};
use aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm as Aes128GcmLib;
use std::fmt::Debug;

/// Structure implementing `SymmetricCrypto` and the `DEM` interfaces based on
/// AES 128 GCM.
pub struct Aes128Gcm(Aes128GcmLib);

impl Debug for Aes128Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes128Gcm").finish()
    }
}

impl Aes128Gcm {
    /// Use a 128-bit AES key.
    pub const KEY_LENGTH: usize = 16;

    /// Use a 96-bit nonce.
    pub const NONCE_LENGTH: usize = 12;

    /// Use a 128-bit MAC tag.
    pub const MAC_LENGTH: usize = 16;

    /// Plaintext size (in bytes) restriction from the NIST
    /// <https://csrc.nist.gov/publications/detail/sp/800-38d/final>
    const MAX_PLAINTEXT_LENGTH: u64 = 68_719_476_704; // (2 ^ 39 - 256) / 8
}

impl Dem<{ Aes128Gcm::KEY_LENGTH }, { Aes128Gcm::NONCE_LENGTH }, { Aes128Gcm::MAC_LENGTH }>
    for Aes128Gcm
{
    type SymmetricKey = SymmetricKey<{ Aes128Gcm::KEY_LENGTH }>;
    type Nonce = Nonce<{ Aes128Gcm::NONCE_LENGTH }>;

    fn new(symmetric_key: &Self::SymmetricKey) -> Self {
        Self(Aes128GcmLib::new(GenericArray::from_slice(
            symmetric_key.as_bytes(),
        )))
    }

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        if plaintext.len() as u64 > Self::MAX_PLAINTEXT_LENGTH {
            return Err(CryptoCoreError::PlaintextTooBigError {
                plaintext_len: plaintext.len(),
                max: Self::MAX_PLAINTEXT_LENGTH,
            });
        }
        // allocate correct byte number
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
        if ciphertext.len() as u64 > Self::MAX_PLAINTEXT_LENGTH + Self::MAC_LENGTH as u64 {
            return Err(CryptoCoreError::CiphertextTooBigError {
                ciphertext_len: ciphertext.len(),
                max: Self::MAX_PLAINTEXT_LENGTH + Self::MAC_LENGTH as u64,
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

impl AeadExtra for Aes128Gcm {
    type Algo = Aes128GcmLib;
}

#[cfg(test)]
mod tests {

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{aes_128_gcm::Aes128Gcm, key::SymmetricKey, nonce::Nonce, Dem},
        CryptoCoreError, CsRng, SecretCBytes,
    };

    #[test]
    fn test_dem() -> Result<(), CryptoCoreError> {
        let message = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let nonce = Nonce::new(&mut rng);

        // Encrypt
        let ciphertext = Aes128Gcm::new(&secret_key).encrypt(&nonce, message, additional_data)?;

        // decrypt
        let plaintext =
            Aes128Gcm::new(&secret_key).decrypt(&nonce, &ciphertext, additional_data)?;
        assert_eq!(plaintext, message, "Decryption failed");
        Ok(())
    }
}
