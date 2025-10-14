use std::{
    iter::Sum,
    ops::{Add, Div, Mul, Sub},
};

use curve25519_dalek::Scalar;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "ser")]
use crate::bytes_ser_de::{Deserializer, Serializable, Serializer};
use crate::{CBytes, CryptoCoreError, FixedSizeCBytes, RandomFixedSizeCBytes, SecretCBytes};

pub const R25519_PRIVATE_KEY_LENGTH: usize = 32;

#[derive(Hash, Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct R25519PrivateKey(pub(crate) Scalar);

impl CBytes for R25519PrivateKey {}

impl FixedSizeCBytes<{ R25519_PRIVATE_KEY_LENGTH }> for R25519PrivateKey {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(bytes: [u8; Self::LENGTH]) -> Result<Self, CryptoCoreError> {
        <Option<_>>::from(Scalar::from_canonical_bytes(bytes))
            .map(Self)
            .ok_or_else(|| {
                CryptoCoreError::ConversionError(
                    "given bytes do not represent a canonical scalar".to_string(),
                )
            })
    }
}

impl RandomFixedSizeCBytes<{ R25519_PRIVATE_KEY_LENGTH }> for R25519PrivateKey {
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0; 2 * Self::LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(Scalar::from_bytes_mod_order_wide(&bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl SecretCBytes<{ R25519_PRIVATE_KEY_LENGTH }> for R25519PrivateKey {}

/// Key Serialization framework
#[cfg(feature = "ser")]
impl Serializable for R25519PrivateKey {
    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        ser.write_bytes(self.as_bytes())
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let bytes = <[u8; Self::LENGTH]>::read(de)?;
        Self::try_from_bytes(bytes).map_err(D::Error::from)
    }
}

/// Facades
///
/// Facades are used to hide the underlying types and provide a more
/// user friendly interface to the user.
impl R25519PrivateKey {
    /// Generate a random private key
    ///
    /// This is a facade to `RandomFixedSizeCBytes::new`
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        <Self as RandomFixedSizeCBytes<R25519_PRIVATE_KEY_LENGTH>>::new(rng)
    }

    /// Get the underlying bytes slice of the private key
    ///
    /// This is a facade to `RandomFixedSizeCBytes::as_bytes`
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        <Self as RandomFixedSizeCBytes<R25519_PRIVATE_KEY_LENGTH>>::as_bytes(self)
    }

    /// Serialize the `PrivateKey` as a non zero scalar
    ///
    /// This is a facade to `<Self as FixedSizeCBytes>::to_bytes`
    #[must_use]
    pub fn to_bytes(&self) -> [u8; R25519_PRIVATE_KEY_LENGTH] {
        <Self as FixedSizeCBytes<R25519_PRIVATE_KEY_LENGTH>>::to_bytes(self)
    }

    /// Deserialize the `PrivateKey` from a non zero scalar
    ///
    /// This is a facade to `<Self as
    /// FixedSizeCBytes<R25519_PRIVATE_KEY_LENGTH>>::try_from_bytes`
    pub fn try_from_bytes(bytes: [u8; R25519_PRIVATE_KEY_LENGTH]) -> Result<Self, CryptoCoreError> {
        <Self as FixedSizeCBytes<R25519_PRIVATE_KEY_LENGTH>>::try_from_bytes(bytes)
    }

    pub fn from_raw_bytes(bytes: &[u8; 64]) -> Self {
        Self(Scalar::from_bytes_mod_order_wide(bytes))
    }

    /// Neutral scalar element for the addition.
    #[inline(always)]
    pub const fn zero() -> Self {
        Self(Scalar::ZERO)
    }

    /// Neutral scalar element for the multiplication.
    #[inline(always)]
    pub const fn one() -> Self {
        Self(Scalar::ONE)
    }
}

// Curve arithmetic

impl Add for R25519PrivateKey {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<&R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn add(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PrivateKey(self.0 + rhs.0)
    }
}

impl Sub<&R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn sub(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PrivateKey(self.0 - rhs.0)
    }
}

impl Mul<&R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn mul(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PrivateKey(self.0 * rhs.0)
    }
}

impl Div<&R25519PrivateKey> for &R25519PrivateKey {
    type Output = Result<R25519PrivateKey, CryptoCoreError>;

    fn div(self, rhs: &R25519PrivateKey) -> Self::Output {
        if rhs.0 == Scalar::ZERO {
            return Err(CryptoCoreError::EllipticCurveError(
                "division by zero".to_string(),
            ));
        }
        Ok(R25519PrivateKey(self.0 * rhs.0.invert()))
    }
}

impl Sum for R25519PrivateKey {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}
