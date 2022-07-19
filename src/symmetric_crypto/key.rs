use crate::{CryptoBaseError, KeyTrait};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    vec::Vec,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "Vec<u8>")]
pub struct Key<const KEY_LENGTH: usize>(pub [u8; KEY_LENGTH]);

impl<const KEY_LENGTH: usize> Key<KEY_LENGTH> {
    /// Generate a new symmetric random `Key`
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key = Self([0_u8; KEY_LENGTH]);
        rng.fill_bytes(&mut key.0);
        key
    }

    const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<const KEY_LENGTH: usize> KeyTrait for Key<KEY_LENGTH> {
    const LENGTH: usize = KEY_LENGTH;

    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoBaseError> {
        Self::try_from(bytes)
    }
}

impl<const KEY_LENGTH: usize> From<&Key<KEY_LENGTH>> for Vec<u8> {
    fn from(k: &Key<KEY_LENGTH>) -> Self {
        k.0.to_vec()
    }
}

impl<const KEY_LENGTH: usize> TryFrom<Vec<u8>> for Key<KEY_LENGTH> {
    type Error = CryptoBaseError;

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
    type Error = CryptoBaseError;

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
