//! Define the `X25519PublicKey` and `X25519PrivateKey` objects, asymmetric
//! keys based on the Curve25519.
//!
//! Curve25519 is an elliptic curve defined by the equation `y^2 = x^3 + 486662x^2 + x`.
//! Its security level is 128-bits. It is the fastest curve available at the
//! time of this implementation.

use crate::{asymmetric_crypto::DhKeyPair, CryptoCoreError, KeyTrait};
use core::{
    convert::TryFrom,
    fmt::Display,
    ops::{Add, Div, Mul, Sub},
};
use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 secret key length
pub const X25519_SK_LENGTH: usize = 32;

/// X25519 public key length
pub const X25519_PK_LENGTH: usize = 32;

/// Asymmetric private key based on Curve25519.
///
/// Internally, a curve scalar is used. It is 128-bits long.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "[u8; 32]")]
pub struct X25519PrivateKey(Scalar);

impl X25519PrivateKey {
    /// Convert to bytes without copy.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl KeyTrait<X25519_SK_LENGTH> for X25519PrivateKey {
    /// Generate a new random key.
    #[inline]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        Self(Scalar::from_bytes_mod_order_wide(&bytes))
    }

    /// Converts the given key into bytes.
    #[inline]
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    /// Converts the given bytes into key.
    #[inline]
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        Self::try_from(bytes)
    }
}

impl TryFrom<[u8; Self::LENGTH]> for X25519PrivateKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: [u8; Self::LENGTH]) -> Result<Self, Self::Error> {
        let scalar = Scalar::from_canonical_bytes(bytes).ok_or_else(|| {
            Self::Error::ConversionError(
                "Given bytes do not represent a canonical Scalar!".to_string(),
            )
        })?;
        Ok(Self(scalar))
    }
}

impl TryFrom<&[u8]> for X25519PrivateKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; Self::LENGTH] = bytes.try_into().map_err(|e| {
            Self::Error::ConversionError(format!(
                "Error while converting slice of size {} to `X25519PublicKey`: {}",
                bytes.len(),
                e,
            ))
        })?;
        Self::try_from(bytes)
    }
}

// Needed by serde to derive `Deserialize`. Do not use otherwise since there
// is a copy anyway
impl From<X25519PrivateKey> for [u8; X25519_SK_LENGTH] {
    #[inline]
    fn from(key: X25519PrivateKey) -> Self {
        key.to_bytes()
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PrivateKey {
    type Error = CryptoCoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Self::try_from(bytes.as_slice())
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl<'a> Add<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 * rhs.0)
    }
}

impl<'a> Div<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn div(self, rhs: &X25519PrivateKey) -> Self::Output {
        #[allow(clippy::suspicious_arithmetic_impl)]
        X25519PrivateKey(self.0 * rhs.0.invert())
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

impl ZeroizeOnDrop for X25519PrivateKey {}

/// Asymmetric public key based on Curve25519.
///
/// Internally, a Ristretto point is used. It is 256-bits long, but its
/// compressed form is used for serialization, which makes it 128-bits long.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "[u8; 32]")]
pub struct X25519PublicKey(RistrettoPoint);

impl KeyTrait<X25519_PK_LENGTH> for X25519PublicKey {
    /// Generate a new random public key.
    #[inline]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut uniform_bytes = [0u8; 64];
        rng.fill_bytes(&mut uniform_bytes);
        Self(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }

    /// Converts the given public key into an array of bytes.
    #[inline]
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.compress().to_bytes()
    }

    #[inline]
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        Self::try_from(bytes)
    }
}

impl From<X25519PrivateKey> for X25519PublicKey {
    fn from(private_key: X25519PrivateKey) -> Self {
        Self(&private_key.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl From<&X25519PrivateKey> for X25519PublicKey {
    fn from(private_key: &X25519PrivateKey) -> Self {
        Self(&private_key.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl TryFrom<[u8; Self::LENGTH]> for X25519PublicKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: [u8; Self::LENGTH]) -> Result<Self, Self::Error> {
        Ok(Self(CompressedRistretto(bytes).decompress().ok_or_else(
            || {
                CryptoCoreError::ConversionError(
                    "Cannot decompress given bytes into a valid curve point!".to_string(),
                )
            },
        )?))
    }
}

impl TryFrom<&[u8]> for X25519PublicKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; Self::LENGTH] = bytes.try_into().map_err(|e| {
            Self::Error::ConversionError(format!(
                "Error while converting slice of size {} to `X25519PublicKey`: {}",
                bytes.len(),
                e,
            ))
        })?;
        Self::try_from(bytes)
    }
}

// Needed by serde to derive `Deserialize`. Do not use otherwise since there
// is a copy anyway.
impl From<X25519PublicKey> for [u8; X25519_PK_LENGTH] {
    #[inline]
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
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0.compress().to_bytes()))
    }
}

impl<'a> Sub<&'a X25519PublicKey> for &X25519PublicKey {
    type Output = X25519PublicKey;

    fn sub(self, rhs: &X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 - rhs.0)
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

impl Zeroize for X25519PublicKey {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

// Implement `Drop` trait to follow R23.
impl Drop for X25519PublicKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for X25519PublicKey {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519KeyPair {
    pk: X25519PublicKey,
    sk: X25519PrivateKey,
}

impl DhKeyPair<X25519_PK_LENGTH, X25519_SK_LENGTH> for X25519KeyPair {
    type PublicKey = X25519PublicKey;

    type PrivateKey = X25519PrivateKey;

    #[inline]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = X25519PrivateKey::new(rng);
        let pk = X25519PublicKey::from(&sk);
        Self { sk, pk }
    }

    #[inline]
    fn public_key(&self) -> &Self::PublicKey {
        &self.pk
    }

    #[inline]
    fn private_key(&self) -> &Self::PrivateKey {
        &self.sk
    }
}

impl Zeroize for X25519KeyPair {
    fn zeroize(&mut self) {
        self.pk.zeroize();
        self.sk.zeroize();
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for X25519KeyPair {}

#[cfg(test)]
mod test {
    use crate::{
        asymmetric_crypto::curve25519::{
            X25519PrivateKey, X25519PublicKey, X25519_PK_LENGTH, X25519_SK_LENGTH,
        },
        entropy::CsRng,
        KeyTrait,
    };

    #[test]
    fn test_private_key_serialization() {
        let mut rng = CsRng::new();
        let sk = X25519PrivateKey::new(&mut rng);
        let bytes: [u8; X25519_SK_LENGTH] = sk.to_bytes();
        let recovered = X25519PrivateKey::try_from(bytes).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_public_key_serialization() {
        let mut rng = CsRng::new();
        let pk = X25519PublicKey::new(&mut rng);
        let bytes: [u8; X25519_PK_LENGTH] = pk.to_bytes();
        let recovered = super::X25519PublicKey::try_from(bytes).unwrap();
        assert_eq!(pk, recovered);
    }
}
