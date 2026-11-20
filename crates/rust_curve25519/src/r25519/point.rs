use super::R25519Scalar;
use core::ops::Mul;
use cosmian_crypto_base::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    implement_abelian_group, implement_monoid_arithmetic,
    reexport::{
        rand_core::CryptoRngCore,
        zeroize::{Zeroize, ZeroizeOnDrop},
    },
    traits::{AbelianGroup, Group, Monoid, One, Sampling},
    Error,
};
use curve25519_dalek::{
    constants::{self},
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::Identity,
};

/// Curve Point of a Ristretto Curve25519.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct R25519Point(pub(crate) RistrettoPoint);

impl Zeroize for R25519Point {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl Drop for R25519Point {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl ZeroizeOnDrop for R25519Point {}

/// Length of a Ristretto curve point in bytes.
pub const R25519_POINT_LENGTH: usize = 32;

impl From<&R25519Point> for [u8; R25519_POINT_LENGTH] {
    fn from(value: &R25519Point) -> Self {
        value.0.compress().to_bytes()
    }
}

impl Monoid for R25519Point {
    fn id() -> Self {
        Self(RistrettoPoint::identity())
    }

    fn op(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sampling for R25519Point {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self::one() * R25519Scalar::random(rng)
    }
}

implement_monoid_arithmetic!(R25519Point);

impl Group for R25519Point {
    fn invert(&self) -> Self {
        Self(-self.0)
    }
}

implement_abelian_group!(R25519Point);

impl One for R25519Point {
    fn one() -> Self {
        Self(constants::RISTRETTO_BASEPOINT_POINT)
    }

    fn is_one(&self) -> bool {
        self.0 == constants::RISTRETTO_BASEPOINT_POINT
    }
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

impl From<R25519Scalar> for R25519Point {
    fn from(s: R25519Scalar) -> Self {
        Self::one() * s
    }
}

impl From<&R25519Scalar> for R25519Point {
    fn from(s: &R25519Scalar) -> Self {
        Self::one() * s
    }
}

impl Serializable for R25519Point {
    type Error = Error;

    fn length(&self) -> usize {
        R25519_POINT_LENGTH
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&self.0.compress().to_bytes())
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok(Self(
            CompressedRistretto(de.read_array::<{ R25519_POINT_LENGTH }>()?)
                .decompress()
                .ok_or_else(|| {
                    Error::GenericDeserializationError(
                        "Cannot decompress given bytes into a valid curve point!".to_string(),
                    )
                })?,
        ))
    }
}

#[cfg(test)]
mod test {
    use super::{R25519Point, R25519Scalar};
    use cosmian_crypto_base::{
        bytes_ser_de::test_serialization,
        reexport::rand_core::SeedableRng,
        traits::{tests::test_abelian_group, One, Sampling},
        CsRng,
    };

    #[test]
    fn test_arithmetic() {
        test_abelian_group::<R25519Point>();
    }

    #[test]
    fn test_public_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519Scalar::random(&mut rng);
        let pk = R25519Point::one() * &sk;
        test_serialization(&pk).unwrap();
    }
}
