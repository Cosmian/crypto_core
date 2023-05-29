use crate::{bytes_ser_de::Serializable, CryptoCoreError, FixedSizeKey, Key, SecretKey};
use curve25519_dalek::Scalar;
use rand_chacha::rand_core::CryptoRngCore;
use std::ops::{Add, Div, Mul, Sub};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Asymmetric private key based on Curve25519.
///
/// This type wraps a scalar which is clamped to the curve.
/// Curve25519PrivateKey should not be used directly
/// but rather re-used as a base type for other final types on the curve
/// such as X22519PrivateKey.
#[derive(Clone, Debug)]
pub struct Curve25519PrivateKey(pub(crate) Scalar);

/// Zeroizes the private key.
impl Zeroize for Curve25519PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Implements `Drop` trait to follow R23.
impl Drop for Curve25519PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Zeroizes the private key on drop.
impl ZeroizeOnDrop for Curve25519PrivateKey {}

/// Compares two private keys.
impl PartialEq for Curve25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

/// Compares two private keys.
impl Eq for Curve25519PrivateKey {}

// Key traits implementations

impl Key for Curve25519PrivateKey {}

impl FixedSizeKey<{ crypto_box::KEY_SIZE }> for Curve25519PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().into()
    }

    fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoCoreError> {
        slice
            .try_into()
            .map(Scalar::from_bits_clamped)
            .map(Self)
            .map_err(|_| crate::CryptoCoreError::InvalidKeyLength)
    }
}

impl SecretKey<{ crypto_box::KEY_SIZE }> for Curve25519PrivateKey {
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0; Self::LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(Scalar::from_bits_clamped(bytes))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Key Serialization framework
impl Serializable for Curve25519PrivateKey {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        ser.write_array(self.as_slice())
    }

    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<{ Self::LENGTH }>()?;
        Self::try_from_slice(&bytes)
    }
}

// Curve arithmetic

impl<'a> Add<&'a Curve25519PrivateKey> for &Curve25519PrivateKey {
    type Output = Curve25519PrivateKey;

    fn add(self, rhs: &Curve25519PrivateKey) -> Self::Output {
        Curve25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a Curve25519PrivateKey> for &Curve25519PrivateKey {
    type Output = Curve25519PrivateKey;

    fn sub(self, rhs: &Curve25519PrivateKey) -> Self::Output {
        Curve25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a Curve25519PrivateKey> for &Curve25519PrivateKey {
    type Output = Curve25519PrivateKey;

    fn mul(self, rhs: &Curve25519PrivateKey) -> Self::Output {
        Curve25519PrivateKey(self.0 * rhs.0)
    }
}

impl<'a> Div<&'a Curve25519PrivateKey> for &Curve25519PrivateKey {
    type Output = Curve25519PrivateKey;

    fn div(self, rhs: &Curve25519PrivateKey) -> Self::Output {
        #[allow(clippy::suspicious_arithmetic_impl)]
        Curve25519PrivateKey(self.0 * rhs.0.invert())
    }
}
