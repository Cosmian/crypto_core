use crate::{bytes_ser_de::Serializable, CryptoCoreError};
use rand_core::CryptoRngCore;
use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Holds a secret information of `LENGTH` bytes.
///
/// This secret is stored on the heap and is guaranteed to be zeroized on drop.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Secret<const LENGTH: usize>(Pin<Box<[u8; LENGTH]>>);

impl<const LENGTH: usize> Secret<LENGTH> {
    /// Creates a new secret and returns it.
    ///
    /// All bytes are initially set to 0.
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

    /// Deterministically derive a new secret from the given secret and
    /// additional information.
    ///
    /// # Error
    ///
    /// Fails to generate the new secret in case the source evidently does not
    /// contain enough entropy. The check performed is based on the respective
    /// new- and source-secret lengths. The source secret needs to be have a
    /// length greater than the desired new-secret length for this check to
    /// pass.
    #[cfg(feature = "sha3")]
    pub fn derive<const SECRET_LENGTH: usize>(
        source: &Secret<SECRET_LENGTH>,
        info: &[u8],
    ) -> Result<Self, CryptoCoreError> {
        use crate::kdf256;

        if info.is_empty() {
            return Err(CryptoCoreError::InvalidBytesLength(
                "info is a required field as it is used as domain separation".to_string(),
                0,
                None,
            ));
        }
        if SECRET_LENGTH < LENGTH {
            return Err(CryptoCoreError::ConversionError(format!(
                "insufficient entropy to derive {}-byte secret from a {}-byte secret",
                LENGTH, SECRET_LENGTH,
            )));
        }
        let mut target = Self::default();
        kdf256!(&mut *target, &**source, info);
        Ok(target)
    }
}

impl<const LENGTH: usize> Default for Secret<LENGTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const LENGTH: usize> Deref for Secret<LENGTH> {
    type Target = [u8; LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> DerefMut for Secret<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LENGTH: usize> Zeroize for Secret<LENGTH> {
    fn zeroize(&mut self) {
        self.0.deref_mut().zeroize()
    }
}

impl<const LENGTH: usize> Drop for Secret<LENGTH> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for Secret<LENGTH> {}

impl<const LENGTH: usize> Serializable for Secret<LENGTH> {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        LENGTH
    }

    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&**self)
    }

    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let mut bytes = de.read_array::<LENGTH>()?;
        Ok(Self::from_unprotected_bytes(&mut bytes))
    }
}
