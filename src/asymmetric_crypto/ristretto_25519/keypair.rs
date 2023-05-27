//! Define the `R25519PublicKey` and `R25519PrivateKey` objects, asymmetric
//! keys based on the Ristretto group for Curve25519.
//!
//! Curve25519 is an elliptic curve defined by the equation `y^2 = x^3 +
//! 486662x^2 + x`. Its security level is 128-bits. It is the fastest curve
//! available at the time of this implementation.
//!
//! See https://ristretto.group/ristretto.html for more information on Ristretto.

use core::{
    convert::TryFrom,
    ops::{Add, Div, Mul, Sub},
};

use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    asymmetric_crypto::DhKeyPair, bytes_ser_de::Serializable, reexport::rand_core::CryptoRngCore,
    CryptoCoreError, KeyTrait,
};

/// R25519 private key length
pub const R25519_PRIVATE_KEY_LENGTH: usize = 32;

/// R25519 public key length
pub const R25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Asymmetric private key based on Curve25519.
///
/// Internally, a curve scalar is used. It is 128-bits long.
#[derive(Hash, Clone, PartialEq, Eq, Debug)]
pub struct R25519PrivateKey(Scalar);

impl R25519PrivateKey {
    /// Converts to bytes without copy.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl KeyTrait<R25519_PRIVATE_KEY_LENGTH> for R25519PrivateKey {
    /// Generates a new random key.
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        Self(Scalar::from_bytes_mod_order_wide(&bytes))
    }

    /// Converts the given key into bytes.
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    /// Converts the given bytes into key.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        Self::try_from(bytes)
    }
}

impl Serializable for R25519PrivateKey {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        ser.write_array(self.as_bytes())
    }

    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Self::try_from(de.read_array::<{ Self::LENGTH }>()?)
    }
}

impl TryFrom<[u8; Self::LENGTH]> for R25519PrivateKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: [u8; Self::LENGTH]) -> Result<Self, Self::Error> {
        match Scalar::from_canonical_bytes(bytes).into() {
            Some(scalar) => Ok(Self(scalar)),
            None => Err(Self::Error::ConversionError(
                "Given bytes do not represent a canonical Scalar!".to_string(),
            )),
        }
    }
}

impl TryFrom<&[u8]> for R25519PrivateKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; Self::LENGTH]>::try_from(bytes)
            .map_err(|e| Self::Error::ConversionError(e.to_string()))?;
        Self::try_from(bytes)
    }
}

// Needed by serde to derive `Deserialize`. Do not use otherwise since there
// is a copy anyway
impl From<R25519PrivateKey> for [u8; R25519_PRIVATE_KEY_LENGTH] {
    fn from(key: R25519PrivateKey) -> Self {
        key.to_bytes()
    }
}

impl<'a> Add<&'a R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn add(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn sub(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn mul(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PrivateKey(self.0 * rhs.0)
    }
}

impl<'a> Div<&'a R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn div(self, rhs: &R25519PrivateKey) -> Self::Output {
        #[allow(clippy::suspicious_arithmetic_impl)]
        R25519PrivateKey(self.0 * rhs.0.invert())
    }
}

impl Zeroize for R25519PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Implements `Drop` trait to follow R23.
impl Drop for R25519PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for R25519PrivateKey {}

/// Asymmetric public key based on the Ristretto Curve25519.
///
/// Internally, a Ristretto point is used. It is 256-bits long, but its
/// compressed form is used for serialization, which makes it 128-bits long.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct R25519PublicKey(RistrettoPoint);

impl KeyTrait<R25519_PUBLIC_KEY_LENGTH> for R25519PublicKey {
    /// Generates a new random public key.
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut uniform_bytes = [0u8; 64];
        rng.fill_bytes(&mut uniform_bytes);
        Self(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }

    /// Converts the given public key into an array of bytes.
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.compress().to_bytes()
    }

    /// Converts the given bytes into key.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        Self::try_from(bytes)
    }
}

impl Serializable for R25519PublicKey {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&self.to_bytes())
    }

    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Self::try_from(de.read_array::<{ Self::LENGTH }>()?)
    }
}

impl From<R25519PrivateKey> for R25519PublicKey {
    fn from(private_key: R25519PrivateKey) -> Self {
        Self(&private_key.0 * constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl From<&R25519PrivateKey> for R25519PublicKey {
    fn from(private_key: &R25519PrivateKey) -> Self {
        Self(&private_key.0 * constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl TryFrom<[u8; Self::LENGTH]> for R25519PublicKey {
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

impl TryFrom<&[u8]> for R25519PublicKey {
    type Error = CryptoCoreError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; Self::LENGTH]>::try_from(bytes)
            .map_err(|e| Self::Error::ConversionError(e.to_string()))?;
        Self::try_from(bytes)
    }
}

// Needed by serde to derive `Deserialize`. Do not use otherwise since there
// is a copy anyway.
impl From<R25519PublicKey> for [u8; R25519_PUBLIC_KEY_LENGTH] {
    fn from(key: R25519PublicKey) -> Self {
        key.to_bytes()
    }
}

impl<'a> Sub<&'a R25519PublicKey> for &R25519PublicKey {
    type Output = R25519PublicKey;

    fn sub(self, rhs: &R25519PublicKey) -> Self::Output {
        R25519PublicKey(self.0 - rhs.0)
    }
}

impl<'a> Add<&'a R25519PublicKey> for &R25519PublicKey {
    type Output = R25519PublicKey;

    fn add(self, rhs: &R25519PublicKey) -> Self::Output {
        R25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a> Mul<&'a R25519PrivateKey> for &R25519PublicKey {
    type Output = R25519PublicKey;

    fn mul(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PublicKey(self.0 * rhs.0)
    }
}

impl Zeroize for R25519PublicKey {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

// Implements `Drop` trait to follow R23.
impl Drop for R25519PublicKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for R25519PublicKey {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R25519KeyPair {
    pk: R25519PublicKey,
    sk: R25519PrivateKey,
}

impl DhKeyPair<R25519_PUBLIC_KEY_LENGTH, R25519_PRIVATE_KEY_LENGTH> for R25519KeyPair {
    type PrivateKey = R25519PrivateKey;
    type PublicKey = R25519PublicKey;

    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let sk = R25519PrivateKey::new(rng);
        let pk = R25519PublicKey::from(&sk);
        Self { pk, sk }
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.pk
    }

    fn private_key(&self) -> &Self::PrivateKey {
        &self.sk
    }
}

impl Zeroize for R25519KeyPair {
    fn zeroize(&mut self) {
        self.pk.zeroize();
        self.sk.zeroize();
    }
}

// Implements `Drop` trait to follow R23.
impl Drop for R25519KeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for R25519KeyPair {}

#[cfg(test)]
mod test {
    use crate::{
        asymmetric_crypto::{
            ristretto_25519::{
                R25519KeyPair, R25519PrivateKey, R25519PublicKey, R25519_PRIVATE_KEY_LENGTH,
                R25519_PUBLIC_KEY_LENGTH,
            },
            DhKeyPair,
        },
        reexport::rand_core::SeedableRng,
        CsRng, KeyTrait,
    };

    #[test]
    fn test_private_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519PrivateKey::new(&mut rng);
        let bytes: [u8; R25519_PRIVATE_KEY_LENGTH] = sk.to_bytes();
        let recovered = R25519PrivateKey::try_from(bytes).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_public_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let pk = R25519PublicKey::new(&mut rng);
        let bytes: [u8; R25519_PUBLIC_KEY_LENGTH] = pk.to_bytes();
        let recovered = super::R25519PublicKey::try_from(bytes).unwrap();
        assert_eq!(pk, recovered);
    }

    #[test]
    fn test_dh_key_pair() {
        let mut rng = CsRng::from_entropy();
        let kp1 = R25519KeyPair::new(&mut rng);
        let kp2 = R25519KeyPair::new(&mut rng);
        // check the keys are randomly generated
        assert_ne!(kp1, kp2);
        // check DH Key exchange is possible
        assert_eq!(
            kp1.public_key() * kp2.private_key(),
            kp2.public_key() * kp1.private_key()
        );
    }
}
