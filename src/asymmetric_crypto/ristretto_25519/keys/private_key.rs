use core::{
    convert::TryFrom,
    ops::{Add, Div, Mul, Sub},
};

use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    bytes_ser_de::Serializable, reexport::rand_core::CryptoRngCore, CryptoCoreError, KeyTrait,
};

/// R25519 private key length
pub const R25519_PRIVATE_KEY_LENGTH: usize = 32;

/// Asymmetric private key based on Curve25519.
///
/// Internally, a curve scalar is used. It is 128-bits long.
#[derive(Hash, Clone, PartialEq, Eq, Debug)]
pub struct R25519PrivateKey(pub(crate) Scalar);

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
