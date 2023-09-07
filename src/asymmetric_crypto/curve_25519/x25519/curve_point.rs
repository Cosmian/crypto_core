use curve25519_dalek::{scalar::clamp_integer, MontgomeryPoint, Scalar};

use super::X25519PrivateKey;
use crate::{CBytes, CryptoCoreError, FixedSizeCBytes};

/// Length of a serialized X25519 curve point in bytes.
pub const X25519_CURVE_POINT_LENGTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct X25519CurvePoint(pub(crate) MontgomeryPoint);

impl CBytes for X25519CurvePoint {}

impl FixedSizeCBytes<{ X25519_CURVE_POINT_LENGTH }> for X25519CurvePoint {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(
        bytes: [u8; X25519_CURVE_POINT_LENGTH],
    ) -> Result<Self, crate::CryptoCoreError> {
        Ok(Self(MontgomeryPoint(bytes)))
    }
}

impl From<&X25519PrivateKey> for X25519CurvePoint {
    fn from(sk: &X25519PrivateKey) -> Self {
        Self(MontgomeryPoint::mul_base(&Scalar::from_bytes_mod_order(
            clamp_integer(sk.0),
        )))
    }
}

impl X25519CurvePoint {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_CURVE_POINT_LENGTH] {
        self.0.as_bytes()
    }

    #[must_use]
    pub fn dh(&self, rhs: &X25519PrivateKey) -> Self {
        Self(self.0 * Scalar::from_bytes_mod_order(clamp_integer(rhs.0)))
    }
}

/// Facade.
///
/// Facades are used to hide the underlying types and provide a more
/// user friendly interface to the user.
impl X25519CurvePoint {
    #[must_use]

    /// Serialize the curve point.
    ///
    /// Facade to [`FixedSizeCBytes::to_bytes`].
    pub fn to_bytes(&self) -> [u8; X25519_CURVE_POINT_LENGTH] {
        <Self as FixedSizeCBytes<X25519_CURVE_POINT_LENGTH>>::to_bytes(self)
    }

    /// Deserialize the curve point.
    ///
    /// Facade to [`FixedSizeCBytes::try_from_bytes`].
    pub fn try_from_bytes(
        bytes: [u8; X25519_CURVE_POINT_LENGTH],
    ) -> Result<Self, crate::CryptoCoreError> {
        <Self as FixedSizeCBytes<X25519_CURVE_POINT_LENGTH>>::try_from_bytes(bytes)
    }

    /// Tries to create the curve point from the given slice of bytes into a
    /// key.
    ///
    /// Facade to [`FixedSizeCBytes::try_from_slice`].
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoCoreError> {
        <Self as FixedSizeCBytes<X25519_CURVE_POINT_LENGTH>>::try_from_slice(slice)
    }
}
