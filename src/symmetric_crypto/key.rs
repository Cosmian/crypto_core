//! Define a symmetric key object of variable size.

use crate::{symmetric_crypto::SymKey, CryptoCoreError, KeyTrait};
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryFrom, fmt::Display, hash::Hash, ops::Deref};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Symmetric key of a given size.
///
/// It is internally built using an array of bytes of the given length.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct Key<const LENGTH: usize>([u8; LENGTH]);

impl<const KEY_LENGTH: usize> Key<KEY_LENGTH> {
    /// Generate a new symmetric random `Key`
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = [0; KEY_LENGTH];
        rng.fill_bytes(&mut key);
        Self(key)
    }
}

impl<const LENGTH: usize> KeyTrait<LENGTH> for Key<LENGTH> {
    /// Convert the given key into bytes.
    #[inline]
    fn to_bytes(&self) -> [u8; LENGTH] {
        self.0.to_owned()
    }

    /// Try to convert the given bytes into a key. Size must be correct.
    #[inline]
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        Self::try_from(bytes)
    }
}

impl<const KEY_LENGTH: usize> SymKey<KEY_LENGTH> for Key<KEY_LENGTH> {
    /// Convert the given key into a byte slice.
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert the given bytes with correct size into a key.
    fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl<const KEY_LENGTH: usize> From<Key<KEY_LENGTH>> for [u8; KEY_LENGTH] {
    fn from(k: Key<KEY_LENGTH>) -> Self {
        k.0
    }
}

impl<const KEY_LENGTH: usize> From<[u8; KEY_LENGTH]> for Key<KEY_LENGTH> {
    fn from(b: [u8; KEY_LENGTH]) -> Self {
        Self(b)
    }
}

impl<'a, const KEY_LENGTH: usize> TryFrom<&'a [u8]> for Key<KEY_LENGTH> {
    type Error = CryptoCoreError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; KEY_LENGTH]>::try_from(bytes)
            .map_err(|e| Self::Error::ConversionError(e.to_string()))?;
        Ok(Self(bytes))
    }
}

impl<const KEY_LENGTH: usize> Display for Key<KEY_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

impl<const KEY_LENGTH: usize> Default for Key<KEY_LENGTH> {
    fn default() -> Self {
        Self([0; KEY_LENGTH])
    }
}

impl<const KEY_LENGTH: usize> Zeroize for Key<KEY_LENGTH> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Implement `Drop` trait to follow R23.
impl<const KEY_LENGTH: usize> Drop for Key<KEY_LENGTH> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const KEY_LENGTH: usize> ZeroizeOnDrop for Key<KEY_LENGTH> {}

impl<const KEY_LENGTH: usize> Deref for Key<KEY_LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {

    use crate::{entropy::CsRng, symmetric_crypto::key::Key};
    use std::ops::Deref;

    const KEY_LENGTH: usize = 32;

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::new();
        let key_1 = Key::<KEY_LENGTH>::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_1.len());
        let key_2 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_2.len());
        assert_ne!(key_1, key_2);
    }

    #[test]
    fn test_key_serialization() {
        let mut cs_rng = CsRng::new();
        let key = Key::<32>::new(&mut cs_rng);
        let bytes = <[u8; 32]>::try_from(key.deref()).unwrap();
        let res = Key::try_from(bytes).unwrap();
        assert_eq!(key, res);
    }
}
