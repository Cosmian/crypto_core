//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 128 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use super::{
    dem::{DemInPlace, Instantiable},
    nonce::Nonce,
};
use crate::{
    symmetric_crypto::{key::SymmetricKey, Dem},
    RandomFixedSizeCBytes,
};
use aead::{generic_array::GenericArray, KeyInit};
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
    pub const MAX_PLAINTEXT_LENGTH: u64 = 68_719_476_704; // (2 ^ 39 - 256) / 8
}

impl Instantiable<{ Aes128Gcm::KEY_LENGTH }> for Aes128Gcm {
    type Secret = SymmetricKey<{ Aes128Gcm::KEY_LENGTH }>;

    fn new(symmetric_key: &Self::Secret) -> Self {
        Self(Aes128GcmLib::new(GenericArray::from_slice(
            symmetric_key.as_bytes(),
        )))
    }
}

impl Dem<{ Aes128Gcm::KEY_LENGTH }, { Aes128Gcm::NONCE_LENGTH }, { Aes128Gcm::MAC_LENGTH }>
    for Aes128Gcm
{
    type AeadAlgo = Aes128GcmLib;
    type Nonce = Nonce<{ Aes128Gcm::NONCE_LENGTH }>;

    fn aead_backend<'a>(&'a self) -> &'a Self::AeadAlgo {
        &self.0
    }
}

impl DemInPlace<{ Aes128Gcm::KEY_LENGTH }, { Aes128Gcm::NONCE_LENGTH }, { Aes128Gcm::MAC_LENGTH }>
    for Aes128Gcm
{
    type AeadInPlaceAlgo = Aes128GcmLib;
    type Nonce = Nonce<{ Aes128Gcm::NONCE_LENGTH }>;

    fn aead_in_place_backend<'a>(&'a self) -> &'a Self::AeadInPlaceAlgo {
        &self.0
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{
            aes_128_gcm::Aes128Gcm, dem::Instantiable, key::SymmetricKey, nonce::Nonce, Dem,
        },
        CryptoCoreError, CsRng, RandomFixedSizeCBytes,
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
