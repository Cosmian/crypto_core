//! Define a symmetric key object of variable size.

use crate::{CryptoCoreError, KeyTrait};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    vec::Vec,
};
use zeroize::Zeroize;

/// Symmetric key of a given size.
///
/// It is internally built using an array of bytes of the given length.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "Vec<u8>")]
pub struct Key<const KEY_LENGTH: usize>([u8; KEY_LENGTH]);

impl<const KEY_LENGTH: usize> Key<KEY_LENGTH> {
    /// Generate a new symmetric random `Key`
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = Self([0_u8; KEY_LENGTH]);
        rng.fill_bytes(&mut key.0);
        key
    }

    /// Convert the given key into a byte slice, without copy.
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const KEY_LENGTH: usize> Default for Key<KEY_LENGTH> {
    fn default() -> Self {
        Self([0; KEY_LENGTH])
    }
}

impl<const KEY_LENGTH: usize> KeyTrait for Key<KEY_LENGTH> {
    const LENGTH: usize = KEY_LENGTH;

    /// Convert the given key into bytes, with copy.
    fn to_bytes(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    /// Try to convert the given bytes into a key. Size must be correct.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        Self::try_from(bytes)
    }
}

impl<const KEY_LENGTH: usize> From<&Key<KEY_LENGTH>> for Vec<u8> {
    fn from(k: &Key<KEY_LENGTH>) -> Self {
        k.0.to_vec()
    }
}

impl<const KEY_LENGTH: usize> TryFrom<Vec<u8>> for Key<KEY_LENGTH> {
    type Error = CryptoCoreError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<const KEY_LENGTH: usize> From<Key<KEY_LENGTH>> for Vec<u8> {
    fn from(key: Key<KEY_LENGTH>) -> Self {
        key.to_bytes()
    }
}

impl<'a, const KEY_LENGTH: usize> TryFrom<&'a [u8]> for Key<KEY_LENGTH> {
    type Error = CryptoCoreError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let b: [u8; KEY_LENGTH] = bytes.try_into().map_err(|_| Self::Error::SizeError {
            given: bytes.len(),
            expected: KEY_LENGTH,
        })?;
        Ok(Self(b))
    }
}

impl<const KEY_LENGTH: usize> From<[u8; KEY_LENGTH]> for Key<KEY_LENGTH> {
    fn from(b: [u8; KEY_LENGTH]) -> Self {
        Self(b)
    }
}

impl<const KEY_LENGTH: usize> From<Key<KEY_LENGTH>> for [u8; KEY_LENGTH] {
    fn from(k: Key<KEY_LENGTH>) -> [u8; KEY_LENGTH] {
        k.0
    }
}

impl<const KEY_LENGTH: usize> Display for Key<KEY_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
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

#[cfg(test)]
mod tests {

    use crate::{entropy::CsRng, symmetric_crypto::key::Key, KeyTrait};

    const KEY_LENGTH: usize = 128;

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::new();
        let key_1 = Key::<KEY_LENGTH>::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_1.as_slice().len());
        let key_2 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_2.as_slice().len());
        assert_ne!(key_1, key_2);
    }

    #[test]
    fn test_key_serialization() {
        let mut cs_rng = CsRng::new();
        let key = Key::<KEY_LENGTH>::new(&mut cs_rng);
        let bytes = key.to_bytes();
        let res = Key::try_from(bytes).unwrap();
        assert_eq!(key, res);
    }
}
