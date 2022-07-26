//! Define the `X25519PublicKey` and `X25519PrivateKey` objects, asymmetric
//! keys based on the Curve25519.
//!
//! Curve25519 is an elliptic curve defined by the equation `y^2 = x^3 + 486662x^2 + x`.
//! Its security level is 128-bits. It is the fastest curve available at the
//! time of this implementation.

use crate::{CryptoCoreError, KeyTrait};
use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    ops::{Add, Mul, Sub},
};
use zeroize::Zeroize;

/// Asymmetric private key based on Curve25519.
///
/// Internally, a curve scalar is used. It is 128-bits long.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "Vec<u8>")]
pub struct X25519PrivateKey(Scalar);

impl X25519PrivateKey {
    /// Generate a new private key.
    #[must_use]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        Self(Scalar::from_bytes_mod_order_wide(&bytes))
    }

    /// Convert to bytes without copy.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Invert the given key for the multiplicative law
    #[inline]
    #[must_use]
    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }
}

impl KeyTrait for X25519PrivateKey {
    const LENGTH: usize = 32;

    /// Convert the given private key into a vector of bytes (with copy).
    #[inline]
    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        Self::try_from(bytes)
    }
}

impl TryFrom<Vec<u8>> for X25519PrivateKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519PrivateKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; <Self>::LENGTH] = bytes.try_into().map_err(|_| Self::Error::SizeError {
            given: bytes.len(),
            expected: <Self>::LENGTH,
        })?;
        let scalar = Scalar::from_canonical_bytes(bytes).ok_or_else(|| {
            Self::Error::ConversionError(
                "Given bytes do not represent a cannonical Scalar!".to_string(),
            )
        })?;
        Ok(Self(scalar))
    }
}

impl From<X25519PrivateKey> for Vec<u8> {
    fn from(key: X25519PrivateKey) -> Self {
        key.to_bytes()
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PrivateKey {
    type Error = CryptoCoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Self::try_from(bytes)
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 * rhs.0)
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 * rhs.0)
    }
}

impl Add for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PrivateKey> for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<X25519PrivateKey> for &'a X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl Sub for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Sub<&'a X25519PrivateKey> for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl Sub<X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Sub<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl Zeroize for X25519PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Implement `Drop` trait to follow R23.
impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Asymmetric public key based on Curve25519.
///
/// Internally, a Ristretto point is used. It is 256-bits long, but its
/// compressed form is used for serialization, which makes it 128-bits long.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "Vec<u8>")]
pub struct X25519PublicKey(RistrettoPoint);

impl X25519PublicKey {
    /// Generate a new random public key.
    #[must_use]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from(&X25519PrivateKey::new(rng))
    }

    /// Convert the given public key into an array of bytes.
    #[inline]
    #[must_use]
    pub fn to_array(&self) -> [u8; Self::LENGTH] {
        self.0.compress().to_bytes()
    }
}

impl KeyTrait for X25519PublicKey {
    const LENGTH: usize = 32;

    /// Convert the given public key into a vector of bytes. If possible,
    /// prefer the use of `to_array()` since it avoids a copy.
    #[inline]
    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.compress().as_bytes().to_vec()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        Self::try_from(bytes)
    }
}

impl From<&X25519PrivateKey> for X25519PublicKey {
    fn from(private_key: &X25519PrivateKey) -> Self {
        Self(&private_key.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl TryFrom<Vec<u8>> for X25519PublicKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519PublicKey {
    type Error = CryptoCoreError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != <Self>::LENGTH {
            return Err(Self::Error::SizeError {
                given: value.len(),
                expected: <Self>::LENGTH,
            });
        };
        let point = CompressedRistretto::from_slice(value)
            .decompress()
            .ok_or_else(|| {
                Self::Error::ConversionError(
                    "Cannot decompress given bytes into a valid curve point!".to_string(),
                )
            })?;
        Ok(Self(point))
    }
}

impl From<X25519PublicKey> for Vec<u8> {
    fn from(key: X25519PublicKey) -> Self {
        key.to_bytes()
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PublicKey {
    type Error = CryptoCoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Self::try_from(bytes.as_slice())
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.compress().to_bytes()))
    }
}

impl Add for X25519PublicKey {
    type Output = Self;

    fn add(self, rhs: X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PublicKey> for X25519PublicKey {
    type Output = X25519PublicKey;

    fn add(self, rhs: &X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PublicKey> for &X25519PublicKey {
    type Output = X25519PublicKey;

    fn add(self, rhs: &X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for &X25519PublicKey {
    type Output = X25519PublicKey;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PublicKey(self.0 * rhs.0)
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for X25519PublicKey {
    type Output = Self;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        asymmetric_crypto::{X25519PrivateKey, X25519PublicKey},
        entropy::CsRng,
        KeyTrait,
    };

    #[test]
    fn test_private_key_serialization() {
        let mut rng = CsRng::new();
        let sk = X25519PrivateKey::new(&mut rng);
        let bytes = sk.to_bytes();
        let recovered = X25519PrivateKey::try_from(bytes).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_public_key_serialization() {
        let mut rng = CsRng::new();
        let pk = X25519PublicKey::new(&mut rng);
        let bytes = pk.to_bytes();
        let recovered = super::X25519PublicKey::try_from(bytes).unwrap();
        assert_eq!(pk, recovered);
    }
}
