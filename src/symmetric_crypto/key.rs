//! Defines a symmetric key object of variable size.

use core::{hash::Hash, ops::Deref};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{RandomFixedSizeCBytes, SecretCBytes};

/// A type that holds symmetric key of a fixed  size.
///
/// It is internally built using an array of bytes of the given length.
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct SymmetricKey<const LENGTH: usize>(pub(crate) [u8; LENGTH]);

impl<const LENGTH: usize> crate::CBytes for SymmetricKey<LENGTH> {}

impl<const LENGTH: usize> crate::FixedSizeCBytes<LENGTH> for SymmetricKey<LENGTH> {
    fn to_bytes(&self) -> [u8; LENGTH] {
        self.0
    }

    fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, crate::CryptoCoreError> {
        Ok(Self(bytes))
    }
}

impl<const LENGTH: usize> RandomFixedSizeCBytes<LENGTH> for SymmetricKey<LENGTH> {
    fn new<R: rand_chacha::rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        let mut key = [0; LENGTH];
        rng.fill_bytes(&mut key);
        Self(key)
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

/// The symmetric key is a secret and must be zeroized.
impl<const LENGTH: usize> SecretCBytes<LENGTH> for SymmetricKey<LENGTH> {}

impl<const LENGTH: usize> Zeroize for SymmetricKey<LENGTH> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Implements `Drop` trait to follow R23.
impl<const LENGTH: usize> Drop for SymmetricKey<LENGTH> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for SymmetricKey<LENGTH> {}

impl<const LENGTH: usize> Deref for SymmetricKey<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        reexport::rand_core::SeedableRng, symmetric_crypto::key::SymmetricKey, CsRng,
        RandomFixedSizeCBytes,
    };

    const KEY_LENGTH: usize = 32;

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::from_entropy();
        let key_1 = SymmetricKey::<KEY_LENGTH>::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_1.len());
        let key_2 = SymmetricKey::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_2.len());
        assert_ne!(key_1, key_2);
    }
}
