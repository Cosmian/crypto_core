use std::ops::Mul;

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    implement_abelian_group, implement_monoid_arithmetic,
    reexport::rand_core::CryptoRngCore,
    traits::{AbelianGroup, Group, Monoid, One, Sampling},
    CryptoCoreError,
};
use elliptic_curve::group::GroupEncoding;
use p256::ProjectivePoint;

use crate::p256::P256Scalar;

const SERIALIZED_POINT_LENGTH: usize = 33;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256Point(ProjectivePoint);

impl Sampling for P256Point {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(<ProjectivePoint as elliptic_curve::group::Group>::random(
            rng,
        ))
    }
}

impl Monoid for P256Point {
    fn id() -> Self {
        Self(ProjectivePoint::IDENTITY)
    }

    fn op(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

implement_monoid_arithmetic!(P256Point);

impl Group for P256Point {
    fn invert(&self) -> Self {
        Self(-self.0)
    }
}

implement_abelian_group!(P256Point);

impl Serializable for P256Point {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        SERIALIZED_POINT_LENGTH
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&self.0.to_bytes())
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<SERIALIZED_POINT_LENGTH>()?;
        let point = ProjectivePoint::from_bytes(&bytes.into())
            .into_option()
            .ok_or_else(|| {
                CryptoCoreError::GenericDeserializationError("cannot deserialize point".to_string())
            })?;
        Ok(Self(point))
    }
}

impl One for P256Point {
    fn one() -> Self {
        Self(ProjectivePoint::GENERATOR)
    }

    fn is_one(&self) -> bool {
        self == &Self::one()
    }
}

impl Mul<P256Scalar> for P256Point {
    type Output = Self;

    fn mul(self, rhs: P256Scalar) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<&P256Scalar> for P256Point {
    type Output = Self;

    fn mul(self, rhs: &P256Scalar) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<P256Scalar> for &P256Point {
    type Output = P256Point;

    fn mul(self, rhs: P256Scalar) -> Self::Output {
        P256Point(self.0 * rhs.0)
    }
}

impl Mul<&P256Scalar> for &P256Point {
    type Output = P256Point;

    fn mul(self, rhs: &P256Scalar) -> Self::Output {
        P256Point(self.0 * rhs.0)
    }
}

impl From<P256Scalar> for P256Point {
    fn from(s: P256Scalar) -> Self {
        Self::one() * s
    }
}

impl From<&P256Scalar> for P256Point {
    fn from(s: &P256Scalar) -> Self {
        Self::one() * s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng,
        traits::tests::test_group, CsRng,
    };

    #[test]
    fn test_p256_point() {
        test_group::<P256Point>();

        // Test serialization.
        let mut rng = CsRng::from_entropy();
        let p = P256Point::random(&mut rng);
        test_serialization(&p).unwrap();
    }
}
