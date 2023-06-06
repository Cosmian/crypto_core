//! Defines a nonce object, for use in symmetric encryption.
//!
//! A nonce, for Number used ONCE, is a randomly generated number used to
//! ensure a ciphertext cannot be reused, hence avoiding replay attacks.

use core::{convert::TryFrom, fmt::Debug};

use crate::{reexport::rand_core::CryptoRngCore, CBytes, CryptoCoreError, FixedSizeCBytes};

/// Nonce object of the given size.
///
/// Internally, it uses an array of bytes of the given size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce<const LENGTH: usize>(pub [u8; LENGTH]);

impl<const LENGTH: usize> CBytes for Nonce<LENGTH> {}

impl<const LENGTH: usize> FixedSizeCBytes<LENGTH> for Nonce<LENGTH> {
    fn to_bytes(&self) -> [u8; LENGTH] {
        self.0
    }

    fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, CryptoCoreError> {
        Ok(Self(bytes))
    }
}

impl<const LENGTH: usize> Nonce<LENGTH> {
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0; LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn xor(&self, b2: &[u8]) -> Self {
        let mut n = self.0;
        for (ni, bi) in n.iter_mut().zip(b2) {
            *ni ^= bi
        }
        Self(n)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a, const LENGTH: usize> TryFrom<&'a [u8]> for Nonce<LENGTH> {
    type Error = CryptoCoreError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(bytes)
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for Nonce<LENGTH> {
    fn from(b: [u8; LENGTH]) -> Self {
        Self(b)
    }
}

#[cfg(test)]
mod tests {
    use crate::{reexport::rand_core::SeedableRng, symmetric_crypto::nonce::Nonce, CsRng};

    const NONCE_LENGTH: usize = 12;

    #[test]
    fn test_nonce() {
        let mut cs_rng = CsRng::from_entropy();
        let nonce_1 = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_1.as_bytes().len());
        let nonce_2 = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_2.as_bytes().len());
        assert_ne!(nonce_1, nonce_2);
    }
}
