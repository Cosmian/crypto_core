use core::ops::{Add, Mul, Sub};

use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::Identity,
};
use zeroize::Zeroize;

use super::R25519PrivateKey;
#[cfg(feature = "ser")]
use crate::bytes_ser_de::Serializable;
use crate::{CBytes, CryptoCoreError, FixedSizeCBytes};

/// Curve Point of a Ristretto Curve25519.
///
/// Internally, a Ristretto point is used. It wraps an Edwards point and its
/// compressed form is used for serialization, which makes it 256-bit long.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct R25519CurvePoint(pub(crate) RistrettoPoint);

impl CBytes for R25519CurvePoint {}

/// Length of a Ristretto curve point in bytes.
pub const R25519_CURVE_POINT_LENGTH: usize = 32;

impl FixedSizeCBytes<R25519_CURVE_POINT_LENGTH> for R25519CurvePoint {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.compress().to_bytes()
    }

    fn try_from_bytes(
        bytes: [u8; R25519_CURVE_POINT_LENGTH],
    ) -> Result<Self, crate::CryptoCoreError> {
        Ok(Self(CompressedRistretto(bytes).decompress().ok_or_else(
            || {
                CryptoCoreError::ConversionError(
                    "Cannot decompress given bytes into a valid curve point!".to_string(),
                )
            },
        )?))
    }
}

impl From<&R25519PrivateKey> for R25519CurvePoint {
    fn from(private_key: &R25519PrivateKey) -> Self {
        Self(RistrettoPoint::mul_base(&private_key.0))
    }
}

#[cfg(feature = "ser")]
impl Serializable for R25519CurvePoint {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&self.0.compress().to_bytes())
    }

    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Self::try_from_bytes(de.read_array::<{ Self::LENGTH }>()?)
    }
}

impl From<R25519PrivateKey> for R25519CurvePoint {
    fn from(private_key: R25519PrivateKey) -> Self {
        Self(&private_key.0 * constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl Sub<&R25519CurvePoint> for &R25519CurvePoint {
    type Output = R25519CurvePoint;

    fn sub(self, rhs: &R25519CurvePoint) -> Self::Output {
        R25519CurvePoint(self.0 - rhs.0)
    }
}

impl Add<&R25519CurvePoint> for &R25519CurvePoint {
    type Output = R25519CurvePoint;

    fn add(self, rhs: &R25519CurvePoint) -> Self::Output {
        R25519CurvePoint(self.0 + rhs.0)
    }
}

impl Mul<&R25519PrivateKey> for &R25519CurvePoint {
    type Output = R25519CurvePoint;

    fn mul(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519CurvePoint(self.0 * rhs.0)
    }
}

/// Facade.
///
/// Facades are used to hide the underlying types and provide a more
/// user friendly interface to the user.
impl R25519CurvePoint {
    /// Serialize the curve point.
    ///
    /// Facade to [`FixedSizeCBytes::to_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> [u8; R25519_CURVE_POINT_LENGTH] {
        <Self as FixedSizeCBytes<R25519_CURVE_POINT_LENGTH>>::to_bytes(self)
    }

    /// Deserialize the curve point.
    ///
    /// Facade to [`FixedSizeCBytes::try_from_bytes`].
    pub fn try_from_bytes(
        bytes: [u8; R25519_CURVE_POINT_LENGTH],
    ) -> Result<Self, crate::CryptoCoreError> {
        <Self as FixedSizeCBytes<R25519_CURVE_POINT_LENGTH>>::try_from_bytes(bytes)
    }

    /// Tries to create the curve point from the given slice of bytes into a
    /// key.
    ///
    /// Facade to [`FixedSizeCBytes::try_from_slice`].
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoCoreError> {
        <Self as FixedSizeCBytes<R25519_CURVE_POINT_LENGTH>>::try_from_slice(slice)
    }

    /// Returns the identity element of the curve.
    #[must_use]
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }
}

#[cfg(test)]
mod test {
    use super::{R25519CurvePoint, R25519PrivateKey};
    use crate::{reexport::rand_core::SeedableRng, CsRng};

    #[test]
    fn test_private_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519PrivateKey::new(&mut rng);
        let bytes = sk.to_bytes();
        let recovered = R25519PrivateKey::try_from_bytes(bytes).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_public_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519PrivateKey::new(&mut rng);
        let pk = R25519CurvePoint::from(&sk);
        let bytes = pk.to_bytes();
        let recovered = R25519CurvePoint::try_from_bytes(bytes).unwrap();
        assert_eq!(pk, recovered);
    }
}
