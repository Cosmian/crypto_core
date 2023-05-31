//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 256 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use super::dem::DemExtra;
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
        res.append(&mut Aes256Gcm::encrypt_combined(
            secret_key.as_bytes(),
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
        Aes256Gcm::decrypt_combined(
            secret_key.as_bytes(),
            &ciphertext[Self::Nonce::LENGTH..],
            &ciphertext[..Self::Nonce::LENGTH],
            additional_data,
        )
    }
}

impl DemExtra<Aes256GcmLib> for Aes256Gcm {}

#[cfg(test)]
mod tests {

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{aes_256_gcm::Aes256Gcm, key::SymmetricKey, Dem},
        CryptoCoreError, CsRng, SecretKey,
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
}
