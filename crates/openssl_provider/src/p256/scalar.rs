use crate::{p256::NID, FFIMonad};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    implement_abelian_group, implement_commutative_ring, implement_monoid_arithmetic,
    reexport::rand_core::CryptoRngCore,
    traits::{AbelianGroup, Field, Group, Monoid, Ring, Sampling, Zero},
    CryptoCoreError,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    error::ErrorStack,
};
use std::ops::Div;
use zeroize::ZeroizeOnDrop;

fn clone_big_num(n: &BigNum) -> Result<BigNum, ErrorStack> {
    BigNum::from_slice(&n.to_vec())
}

fn get_group_order(ctxt: &mut BigNumContext) -> Result<BigNum, ErrorStack> {
    let mut order = BigNum::new()?;
    let group = EcGroup::from_curve_name(NID)?;
    group.order(&mut order, ctxt)?;
    Ok(order)
}

#[derive(Debug)]
pub struct P256Scalar(pub(crate) Result<BigNum, ErrorStack>);

impl FFIMonad for P256Scalar {
    type Error = ErrorStack;

    fn is_ok(&self) -> bool {
        self.0.is_ok()
    }

    fn manage_error<E: std::error::Error>(self, f: fn(Self::Error) -> E) -> Result<Self, E> {
        self.0.map(Ok).map(Self).map_err(f)
    }
}

impl ZeroizeOnDrop for P256Scalar {}

impl Clone for P256Scalar {
    fn clone(&self) -> Self {
        match &self.0 {
            Ok(n) => Self(clone_big_num(n)),
            Err(e) => Self(Err(e.clone())),
        }
    }
}

impl PartialEq for P256Scalar {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Ok(lhs), Ok(rhs)) => lhs == rhs,
            // OpenSSL bindings do not implement the correct equality traits for
            // the error type and it seems hard to fix it here. Considering that
            // two scalars in an error state are not equal seems okay to work
            // with, but it leaks implementation details...
            (Err(_), Err(_)) | (Ok(_), Err(_)) | (Err(_), Ok(_)) => false,
        }
    }
}

impl Eq for P256Scalar {}

impl Sampling for P256Scalar {
    fn random(_rng: &mut impl CryptoRngCore) -> Self {
        Self(
            EcGroup::from_curve_name(NID)
                .and_then(|group| EcKey::generate(&group))
                .and_then(|key| key.private_key().to_owned()),
        )
    }
}

impl Monoid for P256Scalar {
    fn id() -> Self {
        Self(BigNum::from_u32(0))
    }

    fn op(&self, rhs: &Self) -> Self {
        let op = |lhs: &BigNum, rhs: &BigNum| {
            let mut ctxt = BigNumContext::new()?;
            let mut res = BigNum::new()?;
            let order = get_group_order(&mut ctxt)?;
            res.mod_add(lhs, rhs, &order, &mut ctxt)?;
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

implement_monoid_arithmetic!(P256Scalar);

impl Group for P256Scalar {
    fn invert(&self) -> Self {
        let invert = |n: &BigNum| {
            let mut res = clone_big_num(n)?;
            res.set_negative(true);
            Ok(res)
        };
        match &self.0 {
            Ok(n) => Self(invert(n)),
            Err(e) => Self(Err(e.clone())),
        }
    }
}

implement_abelian_group!(P256Scalar);

impl Ring for P256Scalar {
    fn id() -> Self {
        Self(BigNum::from_u32(1))
    }

    fn op(&self, rhs: &Self) -> Self {
        let op = |lhs: &BigNum, rhs: &BigNum| {
            let mut ctxt = BigNumContext::new()?;
            let mut res = BigNum::new()?;
            let order = get_group_order(&mut ctxt)?;
            res.mod_mul(lhs, rhs, &order, &mut ctxt)?;
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

implement_commutative_ring!(P256Scalar);

impl Field for P256Scalar {
    type InvError = CryptoCoreError;

    fn invert(&self) -> Result<Self, Self::InvError> {
        let invert = |n: &BigNum| {
            let mut ctxt = BigNumContext::new()?;
            let mut res = BigNum::new()?;
            let order = get_group_order(&mut ctxt)?;
            res.mod_inverse(n, &order, &mut ctxt)?;
            Ok(res)
        };
        match &self.0 {
            Ok(n) => {
                if self.is_zero() {
                    return Err(CryptoCoreError::EllipticCurveError(
                        "monoid identity scalar has no inverse".to_string(),
                    ));
                }
                invert(n).map(|n| Self(Ok(n))).map_err(|e: ErrorStack| {
                    CryptoCoreError::EllipticCurveError(format!(
                        "error occurred upon inverting the scalar: {e}"
                    ))
                })
            }
            Err(e) => Err(CryptoCoreError::EllipticCurveError(format!(
                "cannot invert a scalar in error state: {e}"
            ))),
        }
    }
}

impl Div for P256Scalar {
    type Output = Result<Self, CryptoCoreError>;

    fn div(self, rhs: Self) -> Self::Output {
        <P256Scalar as Field>::invert(&rhs).map(|rhs| self * rhs)
    }
}

impl Div<&P256Scalar> for P256Scalar {
    type Output = Result<Self, CryptoCoreError>;

    fn div(self, rhs: &Self) -> Self::Output {
        <P256Scalar as Field>::invert(rhs).map(|rhs| self * rhs)
    }
}

impl Div<&P256Scalar> for &P256Scalar {
    type Output = Result<P256Scalar, CryptoCoreError>;

    fn div(self, rhs: &P256Scalar) -> Self::Output {
        <P256Scalar as Field>::invert(rhs).map(|rhs| self * &rhs)
    }
}

impl Serializable for P256Scalar {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        32
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match &self.0 {
            Ok(n) => ser.write_array(&n.to_vec()),
            Err(e) => Err(CryptoCoreError::GenericSerializationError(format!(
                "cannot serialize a scalar in error state: {e}"
            ))),
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<32>()?;
        BigNum::from_slice(&bytes).map(Ok).map(Self).map_err(|e| {
            CryptoCoreError::GenericDeserializationError(format!("cannot deserialize scalar: {e}"))
        })
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
