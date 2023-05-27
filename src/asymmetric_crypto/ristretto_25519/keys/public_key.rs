use core::{
    convert::TryFrom,
    ops::{Add, Mul, Sub},
};

use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    bytes_ser_de::Serializable, reexport::rand_core::CryptoRngCore, CryptoCoreError, KeyTrait,
};

use super::R25519PrivateKey;

/// R25519 public key length
pub const R25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Asymmetric public key based on the Ristretto Curve25519.
///
/// Internally, a Ristretto point is used. It is 256-bits long, but its
/// compressed form is used for serialization, which makes it 128-bits long.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct R25519PublicKey(pub(crate) RistrettoPoint);

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
