//! Defines a nonce object, for use in symmetric encryption.
//!
//! A nonce, for Number used ONCE, is a randomly generated number used to
//! ensure a ciphertext cannot be reused, hence avoiding replay attacks.

use crate::CryptoCoreError;
use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display},
};
use rand_core::{CryptoRng, RngCore};

/// Defines a nonce to use in a symmetric encryption scheme.
pub trait NonceTrait: Send + Sync + Sized + Clone {
    /// Size of the nonce in bytes.
    const LENGTH: usize;

    /// Generates a new nonce object.
    #[must_use]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self;

    /// Tries to deserialize the given `bytes` into a nonce object. The number
    /// of `bytes` must be equal to `Self::LENGTH`.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError>;

    /// Xor the nonce with the given value.
    #[must_use]
    fn xor(&self, b2: &[u8]) -> Self;

    /// Serializes the nonce.
    fn as_bytes(&self) -> &[u8];
}

/// Nonce object of the given size.
///
/// Internally, it uses an array of bytes of the given size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce<const NONCE_LENGTH: usize>([u8; NONCE_LENGTH]);

impl<const NONCE_LENGTH: usize> NonceTrait for Nonce<NONCE_LENGTH> {
    const LENGTH: usize = NONCE_LENGTH;

    #[inline]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0; NONCE_LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    #[inline]
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        let b: [u8; NONCE_LENGTH] = bytes.try_into().map_err(|_| CryptoCoreError::SizeError {
            given: bytes.len(),
            expected: NONCE_LENGTH,
        })?;
        Ok(Self(b))
    }

    #[inline]
    fn xor(&self, b2: &[u8]) -> Self {
        let mut n = self.0;
        for (ni, bi) in n.iter_mut().zip(b2) {
            *ni ^= bi
        }
        Self(n)
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'a, const NONCE_LENGTH: usize> TryFrom<&'a [u8]> for Nonce<NONCE_LENGTH> {
    type Error = CryptoCoreError;

    #[inline]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for Nonce<LENGTH> {
    #[inline]
    fn from(b: [u8; LENGTH]) -> Self {
        Self(b)
    }
}

impl<const LENGTH: usize> Display for Nonce<LENGTH> {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        entropy::CsRng,
        symmetric_crypto::nonce::{Nonce, NonceTrait},
    };

    const NONCE_LENGTH: usize = 12;

    #[test]
    fn test_nonce() {
        let mut cs_rng = CsRng::new();
        let nonce_1 = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_1.as_bytes().len());
        let nonce_2 = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_2.as_bytes().len());
        assert_ne!(nonce_1, nonce_2);
    }
}
