use crate::{
    p256::{scalar::P256Scalar, NID},
    FFIMonad,
};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    implement_abelian_group, implement_monoid_arithmetic,
    reexport::rand_core::CryptoRngCore,
    traits::{AbelianGroup, Group, Monoid, One},
    CryptoCoreError, Sampling,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcPoint, PointConversionForm},
    error::ErrorStack,
};
use std::{fmt::Debug, ops::Mul};
use zeroize::ZeroizeOnDrop;

fn clone_point(p: &EcPoint) -> Result<EcPoint, ErrorStack> {
    let mut ctxt = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(NID)?;
    EcPoint::from_bytes(
        &group,
        &p.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctxt)?,
        &mut ctxt,
    )
}

const SERIALIZED_POINT_LENGTH: usize = 33;

pub struct P256Point(Result<EcPoint, ErrorStack>);

impl FFIMonad for P256Point {
    type Error = ErrorStack;

    fn is_ok(&self) -> bool {
        self.0.is_ok()
    }

    fn manage_error<E: std::error::Error>(self, f: fn(Self::Error) -> E) -> Result<Self, E> {
        self.0.map(Ok).map(Self).map_err(f)
    }
}

impl ZeroizeOnDrop for P256Point {}

impl Debug for P256Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Ok(n) => {
                let str = BigNumContext::new().and_then(|mut ctxt| {
                    EcGroup::from_curve_name(NID).and_then(|group| {
                        n.to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctxt)
                    })
                });
                match str {
                    Ok(str) => f.debug_tuple("P256Point").field(&str).finish(),
                    Err(_) => Err(std::fmt::Error),
                }
            }
            Err(e) => write!(f, "P256Point in error state: {e}"),
        }
    }
}

impl Sampling for P256Point {
    fn random(rng: &mut impl CryptoRngCore) -> Self {
        P256Scalar::random(rng).into()
    }
}

impl Clone for P256Point {
    fn clone(&self) -> Self {
        match &self.0 {
            Ok(p) => Self(clone_point(p)),
            Err(e) => Self(Err(e.clone())),
        }
    }
}

impl PartialEq for P256Point {
    fn eq(&self, other: &Self) -> bool {
        let eq = |lhs: &EcPoint, rhs: &EcPoint| {
            let mut ctxt = BigNumContext::new()?;
            let group = EcGroup::from_curve_name(NID)?;
            lhs.eq(&group, rhs, &mut ctxt)
        };
        match (&self.0, &other.0) {
            (Ok(lhs), Ok(rhs)) => eq(lhs, rhs).unwrap_or(false),
            (Ok(_), Err(_)) | (Err(_), Ok(_)) | (Err(_), Err(_)) => false,
        }
    }
}

impl Eq for P256Point {}

impl Monoid for P256Point {
    fn id() -> Self {
        let id = || {
            let group = EcGroup::from_curve_name(NID)?;
            let mut res = EcPoint::new(&group)?;
            let ctxt = BigNumContext::new()?;
            res.mul_generator(&group, &BigNum::from_u32(0).unwrap(), &ctxt)?;
            Ok(res)
        };
        Self(id())
    }

    fn op(&self, rhs: &Self) -> Self {
        let op = |lhs: &EcPoint, rhs: &EcPoint| {
            let group = EcGroup::from_curve_name(NID).unwrap();
            let mut res = EcPoint::new(&group).unwrap();
            let mut ctxt = BigNumContext::new().unwrap();
            res.add(&group, lhs, rhs, &mut ctxt).unwrap();
            Ok(res)
        };
        match (&self.0, &rhs.0) {
            (Ok(lhs), Ok(rhs)) => Self(op(lhs, rhs)),
            (Ok(_), Err(e)) => Self(Err(e.clone())),
            (Err(e), Ok(_)) => Self(Err(e.clone())),
            (Err(lhs), Err(rhs)) => {
                // Merges errors into a single stack.
                lhs.put();
                rhs.put();
                Self(Err(ErrorStack::get()))
            }
        }
    }
}

implement_monoid_arithmetic!(P256Point);

impl Group for P256Point {
    fn invert(&self) -> Self {
        let invert = |p| {
            let mut res = clone_point(p)?;
            let ctxt = BigNumContext::new()?;
            let group = EcGroup::from_curve_name(NID)?;
            res.invert(&group, &ctxt)?;
            Ok(res)
        };
        match &self.0 {
            Ok(p) => Self(invert(p)),
            Err(e) => Self(Err(e.clone())),
        }
    }
}

implement_abelian_group!(P256Point);

impl One for P256Point {
    fn one() -> Self {
        let one = || {
            let group = EcGroup::from_curve_name(NID)?;
            let mut res = EcPoint::new(&group)?;
            let ctxt = BigNumContext::new()?;
            res.mul_generator(&group, &*BigNum::from_u32(1)?, &ctxt)?;
            Ok(res)
        };
        Self(one())
    }

    fn is_one(&self) -> bool {
        self == &Self::one()
    }
}

impl Mul<&P256Scalar> for &P256Point {
    type Output = P256Point;

    fn mul(self, rhs: &P256Scalar) -> Self::Output {
        let mul = |lhs: &EcPoint, rhs: &BigNum| {
            let group = EcGroup::from_curve_name(NID)?;
            let mut res = EcPoint::new(&group)?;
            let ctxt = BigNumContext::new()?;
            res.mul(&group, lhs, rhs, &ctxt)?;
            Ok(res)
        };
        match (&self.0, &rhs.0) {
            (Ok(lhs), Ok(rhs)) => P256Point(mul(lhs, rhs)),
            (Ok(_), Err(e)) => P256Point(Err(e.clone())),
            (Err(e), Ok(_)) => P256Point(Err(e.clone())),
            (Err(lhs), Err(rhs)) => {
                // Merges errors into a single stack.
                lhs.put();
                rhs.put();
                P256Point(Err(ErrorStack::get()))
            }
        }
    }
}

impl Mul<P256Scalar> for P256Point {
    type Output = Self;

    fn mul(self, rhs: P256Scalar) -> Self::Output {
        &self * &rhs
    }
}

impl Mul<&P256Scalar> for P256Point {
    type Output = Self;

    fn mul(self, rhs: &P256Scalar) -> Self::Output {
        &self * rhs
    }
}

impl Mul<P256Scalar> for &P256Point {
    type Output = P256Point;

    fn mul(self, rhs: P256Scalar) -> Self::Output {
        self * &rhs
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

impl Serializable for P256Point {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        SERIALIZED_POINT_LENGTH
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let p = self.0.as_ref().map_err(|e| {
            CryptoCoreError::GenericSerializationError(format!(
                "cannot serialize a P256 point in error state: {e}"
            ))
        })?;
        let bytes = EcGroup::from_curve_name(NID)
            .and_then(|group| {
                BigNumContext::new().and_then(|mut ctxt| {
                    p.to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctxt)
                })
            })
            .map_err(|e| {
                CryptoCoreError::GenericSerializationError(format!(
                    "failed extracting P356 point bytes: {e}"
                ))
            })?;

        ser.write_array(&bytes)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<SERIALIZED_POINT_LENGTH>()?;
        let point = EcGroup::from_curve_name(NID)
            .and_then(|group| {
                BigNumContext::new()
                    .and_then(|mut ctxt| EcPoint::from_bytes(&group, &bytes, &mut ctxt))
            })
            .map_err(|e| CryptoCoreError::GenericDeserializationError(e.to_string()))?;
        Ok(Self(Ok(point)))
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
