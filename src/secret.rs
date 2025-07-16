use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
};

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "ser")]
use crate::bytes_ser_de::Serializable;
use crate::bytes_ser_de::{Deserializer, Serializer};

/// Holds a secret information of `LENGTH` bytes.
///
/// This secret is stored on the heap and is guaranteed to be zeroized on drop.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Secret<const LENGTH: usize>(Pin<Box<[u8; LENGTH]>>);

impl<const LENGTH: usize> Secret<LENGTH> {
    /// Creates a new secret and returns it.
    ///
    /// All bytes are initially set to 0.
    #[inline(always)]
    pub fn new() -> Self {
        Self(Box::pin([0; LENGTH]))
    }

    /// Creates a new random secret using the given RNG.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut secret = Self::new();
        rng.fill_bytes(&mut *secret);
        secret
    }

    /// Returns the bytes of the secret.
    ///
    /// # Safety
    ///
    /// Once returned the secret bytes are *not* protected. It is the caller's
    /// responsibility to guarantee they are not leaked in the memory.
    #[inline(always)]
    pub fn to_unprotected_bytes(&self, dest: &mut [u8; LENGTH]) {
        dest.copy_from_slice(&**self);
    }

    /// Creates a secret from the given unprotected bytes, and zeroizes the
    /// source bytes.
    ///
    /// Do not take ownership of the bytes to avoid stack copying.
    pub fn from_unprotected_bytes(bytes: &mut [u8; LENGTH]) -> Self {
        let mut secret = Self::new();
        secret.copy_from_slice(bytes.as_slice());
        bytes.zeroize();
        secret
    }
}

impl<const LENGTH: usize> Default for Secret<LENGTH> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<const LENGTH: usize> Deref for Secret<LENGTH> {
    type Target = [u8; LENGTH];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> DerefMut for Secret<LENGTH> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LENGTH: usize> Zeroize for Secret<LENGTH> {
    #[inline(always)]
    fn zeroize(&mut self) {
        self.0.deref_mut().zeroize()
    }
}

impl<const LENGTH: usize> Drop for Secret<LENGTH> {
    #[inline(always)]
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for Secret<LENGTH> {}

#[cfg(feature = "ser")]
impl<const LENGTH: usize> Serializable for Secret<LENGTH> {
    fn length(&self) -> usize {
        LENGTH
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        ser.write_bytes(&**self)
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let mut bytes = <[u8; LENGTH]>::read(de)?;
        Ok(Self::from_unprotected_bytes(&mut bytes))
    }
}
