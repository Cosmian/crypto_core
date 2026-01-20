use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    implement_abelian_group, implement_commutative_ring, implement_monoid_arithmetic,
    reexport::{
        rand_core::CryptoRngCore,
        zeroize::{Zeroize, ZeroizeOnDrop},
    },
    traits::{
        AbelianGroup, CBytes, Field, FixedSizeCBytes, Group, Monoid, Ring, Sampling, SecretCBytes,
        Seedable, Zero,
    },
    CryptoCoreError, Secret,
};
use curve25519_dalek::Scalar;
use std::ops::Div;

pub const R25519_SCALAR_LENGTH: usize = 32;

#[derive(Hash, Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct R25519Scalar(pub(crate) Scalar);

impl CBytes for R25519Scalar {}

impl FixedSizeCBytes<{ R25519_SCALAR_LENGTH }> for R25519Scalar {}

impl SecretCBytes<{ R25519_SCALAR_LENGTH }> for R25519Scalar {}

impl Sampling for R25519Scalar {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(Scalar::random(rng))
    }
}

impl Seedable<{ Self::LENGTH }> for R25519Scalar {
    fn from_seed(seed: &Secret<{ Self::LENGTH }>) -> Self {
        let mut bytes = [0; Self::LENGTH];
        seed.to_unprotected_bytes(&mut bytes);
        Self(Scalar::from_bytes_mod_order(bytes))
    }
}

impl Monoid for R25519Scalar {
    fn id() -> Self {
        Self(Scalar::ZERO)
    }

    fn op(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

implement_monoid_arithmetic!(R25519Scalar);

impl Group for R25519Scalar {
    fn invert(&self) -> Self {
        Self(-self.0)
    }
}

implement_abelian_group!(R25519Scalar);

impl Ring for R25519Scalar {
    fn id() -> Self {
        Self(Scalar::ONE)
    }

    fn op(&self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }
}

implement_commutative_ring!(R25519Scalar);

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<&R25519Scalar> for &R25519Scalar {
    type Output = Result<R25519Scalar, CryptoCoreError>;

    fn div(self, rhs: &R25519Scalar) -> Self::Output {
        if rhs.is_zero() {
            Err(CryptoCoreError::EllipticCurveError(
                "scalar division by zero".to_string(),
            ))
        } else {
            Ok(R25519Scalar(self.0 * rhs.0.invert()))
        }
    }
}

impl Div<&R25519Scalar> for R25519Scalar {
    type Output = Result<Self, CryptoCoreError>;

    fn div(self, rhs: &R25519Scalar) -> Self::Output {
        &self / rhs
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for R25519Scalar {
    type Output = Result<Self, CryptoCoreError>;

    fn div(self, rhs: Self) -> Self::Output {
        &self / &rhs
    }
}

impl Field for R25519Scalar {
    type InvError = CryptoCoreError;

    fn invert(&self) -> Result<Self, Self::InvError> {
        if self.is_zero() {
            Err(CryptoCoreError::EllipticCurveError(
                "scalar division by zero".to_string(),
            ))
        } else {
            Ok(Self(self.0.invert()))
        }
    }
}

/// Key Serialization framework
impl Serializable for R25519Scalar {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_array(self.0.as_bytes())
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<{ Self::LENGTH }>()?;
        <Option<_>>::from(Scalar::from_canonical_bytes(bytes))
            .map(Self)
            .ok_or_else(|| {
                CryptoCoreError::ConversionError(
                    "given bytes do not represent a canonical scalar".to_string(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::R25519Scalar;
    use cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng, traits::Sampling, CsRng,
    };

    #[test]
    fn test_private_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519Scalar::random(&mut rng);
        test_serialization(&sk).unwrap();
    }
}
