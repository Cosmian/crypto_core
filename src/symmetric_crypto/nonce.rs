//! Define a nonce object, for use in symmetric encryption.
//!
//! A nonce, for Number used ONCE, is a randomly generated number used to
//! ensure a ciphertext cannot be reused, hence avoiding replay attacks.

use crate::CryptoCoreError;
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use std::{
    cmp::min,
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display},
    vec::Vec,
};

/// Trait defining a nonce for use in a symmetric encryption scheme.
pub trait NonceTrait: Send + Sync + Sized + Clone {
    /// Size of the nonce in bytes.
    const LENGTH: usize;

    /// Generate a new nonce object.
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self;

    /// Try to deserialize the given `bytes` into a nonce object. The number of
    /// `bytes` must be equal to `Self::LENGTH`.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError>;

    /// Increment the nonce by the given value.
    #[must_use]
    fn increment(&self, increment: usize) -> Self;

    /// Xor the nonce with the given value.
    #[must_use]
    fn xor(&self, b2: &[u8]) -> Self;

    /// Serialize the nonce.
    fn as_slice(&self) -> &[u8];
}

/// Nonce object of the given size.
///
/// Internally, it uses an array of bytes of the given size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce<const NONCE_LENGTH: usize>([u8; NONCE_LENGTH]);

impl<const NONCE_LENGTH: usize> NonceTrait for Nonce<NONCE_LENGTH> {
    const LENGTH: usize = NONCE_LENGTH;

    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0_u8; NONCE_LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        let b: [u8; NONCE_LENGTH] = bytes.try_into().map_err(|_| CryptoCoreError::SizeError {
            given: bytes.len(),
            expected: NONCE_LENGTH,
        })?;
        Ok(Self(b))
    }

    fn increment(&self, increment: usize) -> Self {
        let mut bi = BigUint::from_bytes_le(&self.0);
        bi += BigUint::from(increment);
        let mut bi_bytes = bi.to_bytes_le();
        bi_bytes.resize(NONCE_LENGTH, 0);
        Self(bi_bytes.try_into().expect("This should never happen"))
    }

    fn xor(&self, b2: &[u8]) -> Self {
        let mut n = self.0;
        for i in 0..min(b2.len(), NONCE_LENGTH) {
            n[i] ^= b2[i];
        }
        Self(n)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const NONCE_LENGTH: usize> TryFrom<Vec<u8>> for Nonce<NONCE_LENGTH> {
    type Error = CryptoCoreError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from_bytes(&bytes)
    }
}

impl<'a, const NONCE_LENGTH: usize> TryFrom<&'a [u8]> for Nonce<NONCE_LENGTH> {
    type Error = CryptoCoreError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl<const NONCE_LENGTH: usize> From<[u8; NONCE_LENGTH]> for Nonce<NONCE_LENGTH> {
    fn from(b: [u8; NONCE_LENGTH]) -> Self {
        Self(b)
    }
}

impl<const NONCE_LENGTH: usize> From<Nonce<NONCE_LENGTH>> for Vec<u8> {
    fn from(n: Nonce<NONCE_LENGTH>) -> Self {
        n.0.to_vec()
    }
}

impl<const NONCE_LENGTH: usize> Display for Nonce<NONCE_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        entropy::CsRng,
        symmetric_crypto::nonce::{Nonce, NonceTrait},
    };

    const NONCE_LENGTH: usize = 128;

    #[test]
    fn test_nonce() {
        let mut cs_rng = CsRng::new();
        let nonce_1 = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_1.as_slice().len());
        let nonce_2 = Nonce::<NONCE_LENGTH>::new(&mut cs_rng);
        assert_eq!(NONCE_LENGTH, nonce_2.as_slice().len());
        assert_ne!(nonce_1, nonce_2);
    }

    #[test]
    fn test_increment_nonce() {
        const NONCE_LENGTH: usize = 12;
        let mut nonce: Nonce<NONCE_LENGTH> = Nonce::from([0_u8; NONCE_LENGTH]);
        let inc = 1_usize << 10;
        nonce = nonce.increment(inc);
        println!("{}", hex::encode(nonce.0));
        assert_eq!("000400000000000000000000", hex::encode(nonce.0));
    }
}
