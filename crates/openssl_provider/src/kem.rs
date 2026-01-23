use crate::FFIMonad;
use cosmian_crypto_core::{
    bytes_ser_de::Serializable,
    reexport::rand_core::CryptoRngCore,
    traits::{CyclicGroup, Field, KDF, KEM, NIKE},
    CryptoCoreError, Sampling, SymmetricKey,
};
use std::{
    marker::PhantomData,
    ops::{Add, Div, Mul, Neg, Sub},
};
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Copy, Default)]
pub struct MonadicKEM<const KEY_LENGTH: usize, Group: CyclicGroup, Kdf: KDF<KEY_LENGTH>>
where
    Group::Element: FFIMonad,
    Group::Multiplicity: FFIMonad,
    for<'a> &'a Group::Element: Neg<Output = Group::Element>,
    for<'a, 'b> &'a Group::Element: Add<&'b Group::Element, Output = Group::Element>,
    for<'a, 'b> &'a Group::Element: Sub<&'b Group::Element, Output = Group::Element>,
    for<'a, 'b> &'a Group::Element: Mul<Group::Multiplicity, Output = Group::Element>,
    for<'a, 'b> &'a Group::Element: Mul<&'b Group::Multiplicity, Output = Group::Element>,
    for<'a> &'a Group::Multiplicity: Neg<Output = Group::Multiplicity>,
    for<'a, 'b> &'a Group::Multiplicity: Add<&'b Group::Multiplicity, Output = Group::Multiplicity>,
    for<'a, 'b> &'a Group::Multiplicity: Sub<&'b Group::Multiplicity, Output = Group::Multiplicity>,
    for<'a, 'b> &'a Group::Multiplicity: Mul<&'b Group::Multiplicity, Output = Group::Multiplicity>,
    for<'a, 'b> &'a Group::Multiplicity: Div<
        &'b Group::Multiplicity,
        Output = Result<Group::Multiplicity, <Group::Multiplicity as Field>::InvError>,
    >,
{
    data: PhantomData<(Group, Kdf)>,
}

impl<const KEY_LENGTH: usize, Group: CyclicGroup, Kdf: KDF<KEY_LENGTH>> KEM<KEY_LENGTH>
    for MonadicKEM<KEY_LENGTH, Group, Kdf>
where
    Group::Element: FFIMonad + Serializable + ZeroizeOnDrop,
    Group::Multiplicity: FFIMonad + Sampling + ZeroizeOnDrop,
    for<'a> &'a Group::Element: Neg<Output = Group::Element>,
    for<'a, 'b> &'a Group::Element: Add<&'b Group::Element, Output = Group::Element>,
    for<'a, 'b> &'a Group::Element: Sub<&'b Group::Element, Output = Group::Element>,
    for<'a, 'b> &'a Group::Element: Mul<Group::Multiplicity, Output = Group::Element>,
    for<'a, 'b> &'a Group::Element: Mul<&'b Group::Multiplicity, Output = Group::Element>,
    for<'a> &'a Group::Multiplicity: Neg<Output = Group::Multiplicity>,
    for<'a, 'b> &'a Group::Multiplicity: Add<&'b Group::Multiplicity, Output = Group::Multiplicity>,
    for<'a, 'b> &'a Group::Multiplicity: Sub<&'b Group::Multiplicity, Output = Group::Multiplicity>,
    for<'a, 'b> &'a Group::Multiplicity: Mul<&'b Group::Multiplicity, Output = Group::Multiplicity>,
    for<'a, 'b> &'a Group::Multiplicity: Div<
        &'b Group::Multiplicity,
        Output = Result<Group::Multiplicity, <Group::Multiplicity as Field>::InvError>,
    >,
{
    type Encapsulation = Group::Element;

    type EncapsulationKey = Group::Element;

    type DecapsulationKey = Group::Multiplicity;

    type Error = CryptoCoreError;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        let (sk, pk) = <Group as NIKE>::keygen(rng)?;
        let sk = sk.manage_error(|e| {
            CryptoCoreError::EllipticCurveError(format!("secret key is in error state: {e}"))
        })?;
        let pk = pk.manage_error(|e| {
            CryptoCoreError::EllipticCurveError(format!("public key is in error state: {e}"))
        })?;
        Ok((sk, pk))
    }

    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SymmetricKey<KEY_LENGTH>, Self::Encapsulation), Self::Error> {
        let (sk, pk) = <Group as NIKE>::keygen(rng)?;
        let ss = (ek * sk).manage_error(|e| {
            CryptoCoreError::EllipticCurveError(format!("shared secret is in error state: {e}"))
        })?;
        let pk = pk.manage_error(|e| {
            CryptoCoreError::EllipticCurveError(format!("public key is in error state: {e}"))
        })?;
        let key = Kdf::derive(
            &ss.serialize()
                .map_err(|e| CryptoCoreError::GenericDeserializationError(e.to_string()))?,
            &[],
        );
        Ok((key, pk))
    }

    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error> {
        let ss = <Group as NIKE>::shared_secret(dk, enc)?.manage_error(|e| {
            CryptoCoreError::EllipticCurveError(format!("shared secret is in error state: {e}"))
        })?;
        let key = Kdf::derive(
            &ss.serialize()
                .map_err(|e| CryptoCoreError::GenericDeserializationError(e.to_string()))?,
            &[],
        );
        Ok(key)
    }
}
