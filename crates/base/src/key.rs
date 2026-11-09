//! Defines a symmetric key object of variable size.

use core::{hash::Hash, ops::Deref};
use std::ops::DerefMut;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{bytes_ser_de::Serializable, Error};
use crate::{reexport::rand_core::CryptoRngCore, traits::Sampling, Secret};

/// A type that holds symmetric key of a fixed  size.
///
/// It is internally built using an array of bytes of the given length.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey<const LENGTH: usize>(Secret<LENGTH>);

impl<const LENGTH: usize> SymmetricKey<LENGTH> {
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        Self::random(rng)
    }
}

impl<const LENGTH: usize> Sampling for SymmetricKey<LENGTH> {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Secret::random(rng))
    }
}

impl<const LENGTH: usize> Deref for SymmetricKey<LENGTH> {
    type Target = [u8; LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> DerefMut for SymmetricKey<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LENGTH: usize> Default for SymmetricKey<LENGTH> {
    fn default() -> Self {
        Self(Secret::new())
    }
}

impl<const LENGTH: usize> From<Secret<LENGTH>> for SymmetricKey<LENGTH> {
    fn from(secret: Secret<LENGTH>) -> Self {
        Self(secret)
    }
}

impl<const LENGTH: usize> From<SymmetricKey<LENGTH>> for Zeroizing<Vec<u8>> {
    fn from(value: SymmetricKey<LENGTH>) -> Self {
        Zeroizing::new(value.0.to_vec())
    }
}

impl<const LENGTH: usize> Serializable for SymmetricKey<LENGTH> {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        self.0.write(ser)
    }

    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, traits::Sampling,
        CsRng, SymmetricKey,
    };

    const KEY_LENGTH: usize = 32;

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::from_entropy();
        let key_1 = SymmetricKey::<KEY_LENGTH>::random(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_1.len());
        let key_2 = SymmetricKey::random(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_2.len());
        assert_ne!(key_1, key_2);
        test_serialization(&key_1).unwrap();
    }
}
