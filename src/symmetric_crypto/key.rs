//! Defines a symmetric key object of variable size.

use core::{convert::TryFrom, hash::Hash, ops::Deref};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    reexport::rand_core::CryptoRngCore, symmetric_crypto::SymKey, CryptoCoreError, KeyTrait,
};

/// Symmetric key of a given size.
///
/// It is internally built using an array of bytes of the given length.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct Key<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> KeyTrait<LENGTH> for Key<LENGTH> {
    /// Generates a new symmetric random `Key`.
    #[inline]
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut key = [0; LENGTH];
        rng.fill_bytes(&mut key);
        Self(key)
    }

    /// Converts the given key into bytes.
    #[inline]
    fn to_bytes(&self) -> [u8; LENGTH] {
        self.0.to_owned()
    }

    /// Tries to convert the given bytes into a key. Size must be correct.
    #[inline]
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        let bytes = <[u8; LENGTH]>::try_from(bytes)
            .map_err(|e| CryptoCoreError::ConversionError(e.to_string()))?;
        Ok(Self(bytes))
    }
}

impl<const LENGTH: usize> SymKey<LENGTH> for Key<LENGTH> {
    /// Converts the given key into a byte slice.
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the key to return underlying bytes.
    #[inline]
    fn into_bytes(self) -> [u8; LENGTH] {
        self.0
    }

    /// Converts the given bytes with correct size into a key.
    #[inline]
    fn from_bytes(bytes: [u8; LENGTH]) -> Self {
        Self(bytes)
    }
}

impl<const LENGTH: usize> Zeroize for Key<LENGTH> {
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Implements `Drop` trait to follow R23.
impl<const LENGTH: usize> Drop for Key<LENGTH> {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for Key<LENGTH> {}

impl<const LENGTH: usize> Deref for Key<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {

    use crate::{reexport::rand_core::SeedableRng, symmetric_crypto::key::Key, CsRng, KeyTrait};

    const KEY_LENGTH: usize = 32;

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::from_entropy();
        let key_1 = Key::<KEY_LENGTH>::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_1.len());
        let key_2 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_2.len());
        assert_ne!(key_1, key_2);
    }
}
