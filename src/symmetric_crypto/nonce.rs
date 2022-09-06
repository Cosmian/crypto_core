//! Define a nonce object, for use in symmetric encryption.
//!
//! A nonce, for Number used ONCE, is a randomly generated number used to
//! ensure a ciphertext cannot be reused, hence avoiding replay attacks.

use crate::CryptoCoreError;
use core::{
    convert::{TryFrom, TryInto},
    fmt::{Debug, Display},
};
use rand_core::{CryptoRng, RngCore};

/// Trait defining a nonce for use in a symmetric encryption scheme.
pub trait NonceTrait: Send + Sync + Sized + Clone {
    /// Size of the nonce in bytes.
    const LENGTH: usize;

    /// Generate a new nonce object.
    #[must_use]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self;

    /// Try to deserialize the given `bytes` into a nonce object. The number of
    /// `bytes` must be equal to `Self::LENGTH`.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError>;

    /// Increment the nonce by the given value.
    #[must_use]
    fn increment(&self, increment: u64) -> Self;

    /// Xor the nonce with the given value.
    #[must_use]
    fn xor(&self, b2: &[u8]) -> Self;

    /// Serialize the nonce.
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
        let mut bytes = [0_u8; NONCE_LENGTH];
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
    fn increment(&self, increment: u64) -> Self {
        let increment = increment.to_le_bytes();
        assert!(NONCE_LENGTH > 8, "Consider using a longer Nonce!");
        // add the first bytes
        let mut res = [0; NONCE_LENGTH];
        let mut carry = 0;
        for (i, (b1, b2)) in self.0.iter().zip(increment).enumerate() {
            (res[i], carry) = adc(*b1, b2, carry);
        }
        // take into account the potentially remaining carry
        res[increment.len()] = self.0[8] + carry;
        // copy the rest of the input nonce
        for (res, b) in res
            .iter_mut()
            .rev()
            .zip(self.0.iter().rev().take(NONCE_LENGTH - 7))
        {
            *res = *b;
        }
        Self(res)
    }

    #[inline]
    fn xor(&self, b2: &[u8]) -> Self {
        let mut n = [0; NONCE_LENGTH];
        for (i, n_i) in n.iter_mut().enumerate() {
            *n_i = self.0[i] ^ b2[i];
        }
        Self(n)
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[inline]
const fn adc(a: u8, b: u8, carry: u8) -> (u8, u8) {
    let ret = (a as u16) + (b as u16) + (carry as u16);
    (ret as u8, (ret >> 8) as u8)
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

impl<const NONCE_LENGTH: usize> Display for Nonce<NONCE_LENGTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
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

    #[test]
    fn test_increment_nonce() {
        let mut nonce: Nonce<NONCE_LENGTH> = Nonce::from([0_u8; NONCE_LENGTH]);
        let inc = 1 << 10;
        nonce = nonce.increment(inc);
        println!("{}", hex::encode(nonce.0));
        assert_eq!("000400000000000000000000", hex::encode(nonce.0));
    }
}
