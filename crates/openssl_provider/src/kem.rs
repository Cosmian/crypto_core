use crate::{kem::error::KemError, FFIMonad};
use cosmian_crypto_core::{
    bytes_ser_de::Serializable,
    reexport::rand_core::CryptoRngCore,
    traits::{CyclicGroup, Field, KDF, KEM, NIKE},
    Sampling, SymmetricKey,
};
use std::{
    fmt::Debug,
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

impl<const KEY_LENGTH: usize, Group: Debug + CyclicGroup, Kdf: Debug + KDF<KEY_LENGTH>>
    KEM<KEY_LENGTH> for MonadicKEM<KEY_LENGTH, Group, Kdf>
where
    Group::Element: Debug + FFIMonad + Serializable + ZeroizeOnDrop,
    Group::Multiplicity:
        Debug + FFIMonad<Error = <Group::Element as FFIMonad>::Error> + Sampling + ZeroizeOnDrop,
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

    type Error = KemError<KEY_LENGTH, Group, Kdf>;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        let (sk, pk) = <Group as NIKE>::keygen(rng).map_err(Self::Error::Nike)?;
        let sk = sk.manage_error(Self::Error::Ffi)?;
        let pk = pk.manage_error(Self::Error::Ffi)?;
        Ok((sk, pk))
    }

    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SymmetricKey<KEY_LENGTH>, Self::Encapsulation), Self::Error> {
        let (sk, pk) = <Group as NIKE>::keygen(rng).map_err(Self::Error::Nike)?;
        let ss = (ek * sk).manage_error(Self::Error::Ffi)?;
        let pk = pk.manage_error(Self::Error::Ffi)?;
        let key = Kdf::derive(&ss.serialize().map_err(Self::Error::Serialization)?, vec![])
            .map_err(Self::Error::Kdf)?;
        Ok((key, pk))
    }

    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error> {
        let ss = <Group as NIKE>::shared_secret(dk, enc)
            .map_err(Self::Error::Nike)?
            .manage_error(Self::Error::Ffi)?;
        let key = Kdf::derive(&ss.serialize().map_err(Self::Error::Serialization)?, vec![])
            .map_err(Self::Error::Kdf)?;
        Ok(key)
    }
}

mod error {
    use super::*;
    use std::fmt::Display;

    #[derive(Debug)]
    pub enum KemError<const KEY_LENGTH: usize, Nike: NIKE, Kdf: KDF<KEY_LENGTH>>
    where
        Nike::PublicKey: FFIMonad,
    {
        Nike(<Nike as NIKE>::Error),
        Ffi(<Nike::PublicKey as FFIMonad>::Error),
        Serialization(<Nike::PublicKey as Serializable>::Error),
        Kdf(Kdf::Error),
    }

    impl<const KEY_LENGTH: usize, Nike: NIKE, Kdf: KDF<KEY_LENGTH>> Display
        for KemError<KEY_LENGTH, Nike, Kdf>
    where
        Nike::PublicKey: FFIMonad,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Nike(e) => write!(f, "NIKE error in KEM: {e}"),
                Self::Ffi(e) => write!(f, "FFI error in KEM: {e}"),
                Self::Serialization(e) => write!(f, "Serialization error in KEM: {e}"),
                Self::Kdf(e) => write!(f, "KDF error in KEM: {e}"),
            }
        }
    }

    impl<const KEY_LENGTH: usize, Nike: Debug + NIKE, Kdf: Debug + KDF<KEY_LENGTH>>
        std::error::Error for KemError<KEY_LENGTH, Nike, Kdf>
    where
        Nike::PublicKey: Debug + FFIMonad,
    {
    }
}
