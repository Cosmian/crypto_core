//! Define a symmetric key object of variable size.

use crate::{symmetric_crypto::SymKey, CryptoCoreError, KeyTrait};
use core::{convert::TryFrom, fmt::Display, hash::Hash, ops::Deref};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Symmetric key of a given size.
///
/// It is internally built using an array of bytes of the given length.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct Key<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> KeyTrait<LENGTH> for Key<LENGTH> {
    /// Generate a new symmetric random `Key`
    #[inline]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = [0; LENGTH];
        rng.fill_bytes(&mut key);
        Self(key)
    }

    /// Convert the given key into bytes.
    #[inline]
    fn to_bytes(&self) -> [u8; LENGTH] {
        self.0.to_owned()
    }

    /// Try to convert the given bytes into a key. Size must be correct.
    #[inline]
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        let bytes = <[u8; LENGTH]>::try_from(bytes)
            .map_err(|e| CryptoCoreError::ConversionError(e.to_string()))?;
        Ok(Self(bytes))
    }
}

impl<const LENGTH: usize> SymKey<LENGTH> for Key<LENGTH> {
    /// Convert the given key into a byte slice.
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the key to return underlying bytes.
    #[inline]
    fn into_bytes(self) -> [u8; LENGTH] {
        self.0
    }

    /// Convert the given bytes with correct size into a key.
    #[inline]
    fn from_bytes(bytes: [u8; LENGTH]) -> Self {
        Self(bytes)
    }
}

impl<const KEY_LENGTH: usize> Display for Key<KEY_LENGTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
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

    use crate::{entropy::CsRng, symmetric_crypto::key::Key, KeyTrait};

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
}
