use std::ops::Div;

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    implement_abelian_group, implement_commutative_ring, implement_monoid_arithmetic,
    reexport::rand_core::CryptoRngCore,
    traits::{AbelianGroup, Field, Group, Monoid, Ring, Sampling},
    CryptoCoreError,
};
use elliptic_curve::PrimeField;
use p256::Scalar;

const SERIALIZED_SCALAR_LENGTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256Scalar(pub(crate) Scalar);

impl Sampling for P256Scalar {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(<Scalar as elliptic_curve::Field>::random(rng))
    }
}

impl Monoid for P256Scalar {
    fn id() -> Self {
        Self(Scalar::ZERO)
    }

    fn op(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

implement_monoid_arithmetic!(P256Scalar);

impl Group for P256Scalar {
    fn invert(&self) -> Self {
        Self(-self.0)
    }
}

implement_abelian_group!(P256Scalar);

impl Ring for P256Scalar {
    fn id() -> Self {
        Self(Scalar::ONE)
    }

    fn op(&self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }
}

implement_commutative_ring!(P256Scalar);

impl Field for P256Scalar {
    type InvError = CryptoCoreError;

    fn invert(&self) -> Result<Self, Self::InvError> {
        self.0
            .invert()
            .into_option()
            .map(P256Scalar)
            .ok_or_else(|| {
                CryptoCoreError::EllipticCurveError(
                    "monoid identity scalar has no inverse".to_string(),
                )
            })
    }
}

impl Div for P256Scalar {
    type Output = Result<Self, CryptoCoreError>;

    fn div(self, rhs: Self) -> Self::Output {
        <P256Scalar as Field>::invert(&rhs).map(|rhs| P256Scalar(self.0 * rhs.0))
    }
}

impl Div<&P256Scalar> for P256Scalar {
    type Output = Result<Self, CryptoCoreError>;

    fn div(self, rhs: &Self) -> Self::Output {
        <P256Scalar as Field>::invert(rhs).map(|rhs| P256Scalar(self.0 * rhs.0))
    }
}

impl Div<&P256Scalar> for &P256Scalar {
    type Output = Result<P256Scalar, CryptoCoreError>;

    fn div(self, rhs: &P256Scalar) -> Self::Output {
        <P256Scalar as Field>::invert(rhs).map(|rhs| P256Scalar(self.0 * rhs.0))
    }
}

impl Serializable for P256Scalar {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        SERIALIZED_SCALAR_LENGTH
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&self.0.to_bytes())
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<SERIALIZED_SCALAR_LENGTH>()?;
        let scalar = Scalar::from_repr(bytes.into())
            .into_option()
            .ok_or_else(|| {
                CryptoCoreError::GenericDeserializationError(
                    "cannot deserialize scalar".to_string(),
                )
            })?;
        Ok(Self(scalar))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng,
        traits::tests::test_field, CsRng,
    };

    #[test]
    fn test_p256_scalar() {
        test_field::<P256Scalar>();

        // Test serialization.
        let mut rng = CsRng::from_entropy();
        let s = P256Scalar::random(&mut rng);
        test_serialization(&s).unwrap();
    }
}
