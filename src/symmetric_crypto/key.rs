//! Define a symmetric key object of variable size.

use crate::{symmetric_crypto::SymKey, CryptoCoreError, KeyTrait};
use aes::cipher::generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Display, ops::Deref};
use zeroize::Zeroize;

/// Symmetric key of a given size.
///
/// It is internally built using an array of bytes of the given length.
#[derive(Debug, Default, Hash, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key<KeyLength: ArrayLength<u8>>(GenericArray<u8, KeyLength>);

impl<KeyLength: ArrayLength<u8>> Key<KeyLength> {
    /// Generate a new symmetric random `Key`
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = Self(GenericArray::<u8, KeyLength>::default());
        rng.fill_bytes(&mut key.0);
        key
    }
}

impl<KeyLength: Eq + ArrayLength<u8>> KeyTrait for Key<KeyLength> {
    type Length = KeyLength;

    /// Convert the given key into bytes, with copy.
    fn to_bytes(&self) -> generic_array::GenericArray<u8, KeyLength> {
        self.0.clone()
    }

    /// Try to convert the given bytes into a key. Size must be correct.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        Self::try_from(bytes)
    }
}

impl<KeyLength: Eq + ArrayLength<u8>> SymKey for Key<KeyLength> {
    /// Convert the given key into a byte slice, without copy.
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<KeyLength: Eq + ArrayLength<u8>> From<Key<KeyLength>> for GenericArray<u8, KeyLength> {
    fn from(k: Key<KeyLength>) -> Self {
        k.to_bytes()
    }
}

impl<KeyLength: ArrayLength<u8>> From<GenericArray<u8, KeyLength>> for Key<KeyLength> {
    fn from(b: GenericArray<u8, KeyLength>) -> Self {
        Self(b)
    }
}

impl<'a, KeyLength: ArrayLength<u8>> TryFrom<&'a [u8]> for Key<KeyLength> {
    type Error = CryptoCoreError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != KeyLength::to_usize() {
            return Err(Self::Error::SizeError {
                given: bytes.len(),
                expected: KeyLength::to_usize(),
            });
        }
        Ok(Self(GenericArray::<u8, KeyLength>::clone_from_slice(bytes)))
    }
}

impl<KeyLength: ArrayLength<u8>> Display for Key<KeyLength> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_slice()))
    }
}

impl<KeyLength: ArrayLength<u8>> Zeroize for Key<KeyLength> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Implement `Drop` trait to follow R23.
impl<KeyLength: ArrayLength<u8>> Drop for Key<KeyLength> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<KeyLength: ArrayLength<u8>> Deref for Key<KeyLength> {
    type Target = GenericArray<u8, KeyLength>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        entropy::CsRng,
        symmetric_crypto::key::Key,
        typenum::{ToInt, U32},
        KeyTrait,
    };

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::new();
        let key_1 = Key::<U32>::new(&mut cs_rng);
        assert_eq!(<U32 as ToInt<usize>>::to_int(), key_1.len());
        let key_2 = Key::new(&mut cs_rng);
        assert_eq!(<U32 as ToInt<usize>>::to_int(), key_2.len());
        assert_ne!(key_1, key_2);
    }

    #[test]
    fn test_key_serialization() {
        let mut cs_rng = CsRng::new();
        let key = Key::<U32>::new(&mut cs_rng);
        let bytes = key.to_bytes();
        let res = Key::try_from(bytes).unwrap();
        assert_eq!(key, res);
    }
}
