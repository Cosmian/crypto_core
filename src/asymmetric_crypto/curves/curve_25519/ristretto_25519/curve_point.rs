use super::R25519Scalar;
use crate::{
    bytes_ser_de::Serializable,
    implement_abelian_group_arithmetic,
    traits::{AbelianGroup, CBytes, CyclicGroup, FixedSizeCBytes, Group, Monoid, One, Zero},
    CryptoCoreError,
};
use core::iter::Sum;
use curve25519_dalek::{
    constants::{self},
    ristretto::{CompressedRistretto, RistrettoPoint},
};
use std::ops::Mul;
use zeroize::Zeroize;

/// Curve Point of a Ristretto Curve25519.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct R25519Point(pub(crate) RistrettoPoint);

/// Length of a Ristretto curve point in bytes.
pub const R25519_POINT_LENGTH: usize = 32;

impl CBytes for R25519Point {}

impl FixedSizeCBytes<R25519_POINT_LENGTH> for R25519Point {}

impl From<&R25519Point> for [u8; R25519Point::LENGTH] {
    fn from(value: &R25519Point) -> Self {
        value.0.compress().to_bytes()
    }
}

impl Monoid for R25519Point {
    fn id() -> Self {
        Self(constants::RISTRETTO_BASEPOINT_POINT)
    }

    fn op(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Group for R25519Point {
    fn invert(&self) -> Self {
        Self(-self.0)
    }
}

implement_abelian_group_arithmetic!(R25519Point, R25519CurvePoint);

impl AbelianGroup for R25519Point {}

impl One for R25519Point {
    fn one() -> Self {
        Self(constants::RISTRETTO_BASEPOINT_POINT)
    }

    fn is_one(&self) -> bool {
        self.0 == constants::RISTRETTO_BASEPOINT_POINT
    }
}

impl From<&R25519Scalar> for R25519Point {
    fn from(private_key: &R25519Scalar) -> Self {
        Self(&private_key.0 * constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl From<R25519Scalar> for R25519Point {
    fn from(multiplicity: R25519Scalar) -> Self {
        Self::from(&multiplicity)
    }
}

impl CyclicGroup for R25519Point {
    type Multiplicity = R25519Scalar;
}

impl Mul<R25519Scalar> for R25519Point {
    type Output = Self;

    fn mul(self, rhs: R25519Scalar) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<&R25519Scalar> for R25519Point {
    type Output = Self;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<R25519Scalar> for &R25519Point {
    type Output = R25519Point;

    fn mul(self, rhs: R25519Scalar) -> Self::Output {
        R25519Point(self.0 * rhs.0)
    }
}

impl Mul<&R25519Scalar> for &R25519Point {
    type Output = R25519Point;

    fn mul(self, rhs: &R25519Scalar) -> Self::Output {
        R25519Point(self.0 * rhs.0)
    }
}

impl<'a> Sum<&'a R25519Point> for R25519Point {
    fn sum<I: Iterator<Item = &'a R25519Point>>(iter: I) -> Self {
        iter.fold(<Self as Monoid>::id(), |acc, e| {
            <Self as Monoid>::op(&acc, e)
        })
    }
}

impl Serializable for R25519Point {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&self.0.compress().to_bytes())
    }

    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Ok(Self(
            CompressedRistretto(de.read_array::<{ Self::LENGTH }>()?)
                .decompress()
                .ok_or_else(|| {
                    CryptoCoreError::ConversionError(
                        "Cannot decompress given bytes into a valid curve point!".to_string(),
                    )
                })?,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::{R25519Point, R25519Scalar};
    use crate::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, traits::Sampling, CsRng,
    };

    #[test]
    fn test_public_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519Scalar::random(&mut rng);
        let pk = R25519Point::from(&sk);
        test_serialization(&pk).unwrap();
    }
}
