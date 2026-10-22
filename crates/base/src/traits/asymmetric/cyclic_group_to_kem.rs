use crate::{
    bytes_ser_de::Serializable,
    reexport::{rand_core::CryptoRngCore, zeroize::ZeroizeOnDrop},
    traits::{cyclic_group_to_kem::error::KemError, CyclicGroup, Field, Sampling, KDF, KEM, NIKE},
    SymmetricKey,
};
use std::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Add, Div, Mul, Neg, Sub},
};

/// Implement a KEM from a cyclic group.
///
/// Note that a KEM cannot be implemented from the NIKE directly as the NIKE
/// shared secret is not specified. This allows for implementations to return
/// the same type as a public key (as it is done for cyclic groups), or a key.
#[derive(Debug, Clone, Copy, Default)]
pub struct GenericKem<const KEY_LENGTH: usize, Group: CyclicGroup, Kdf: KDF<KEY_LENGTH>>
where
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
    KEM<KEY_LENGTH> for GenericKem<KEY_LENGTH, Group, Kdf>
where
    Group::Element: Debug + Serializable + ZeroizeOnDrop,
    Group::Multiplicity: Sampling + ZeroizeOnDrop,
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
        <Group as NIKE>::keygen(rng).map_err(Self::Error::Nike)
    }

    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SymmetricKey<KEY_LENGTH>, Self::Encapsulation), Self::Error> {
        let (sk, pk) = Self::keygen(rng)?;
        let ss = <Group as NIKE>::shared_secret(&sk, ek).map_err(Self::Error::Nike)?;
        let key = Kdf::derive(&ss.serialize().map_err(Self::Error::Serialization)?, vec![])
            .map_err(Self::Error::Kdf)?;
        Ok((key, pk))
    }

    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error> {
        let ss = <Group as NIKE>::shared_secret(dk, enc).map_err(Self::Error::Nike)?;
        let key = Kdf::derive(&ss.serialize().map_err(Self::Error::Serialization)?, vec![])
            .map_err(Self::Error::Kdf)?;
        Ok(key)
    }
}

mod error {
    use super::*;
    use std::fmt::Display;

    #[derive(Debug)]
    pub enum KemError<const KEY_LENGTH: usize, Nike: NIKE, Kdf: KDF<KEY_LENGTH>> {
        Nike(Nike::Error),
        Serialization(<Nike::PublicKey as Serializable>::Error),
        Kdf(Kdf::Error),
    }

    impl<const KEY_LENGTH: usize, Nike: NIKE, Kdf: KDF<KEY_LENGTH>> Display
        for KemError<KEY_LENGTH, Nike, Kdf>
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Nike(e) => write!(f, "NIKE error in KEM: {e}"),
                Self::Serialization(e) => write!(f, "Serialization error in KEM: {e}"),
                Self::Kdf(e) => write!(f, "KDF error in KEM: {e}"),
            }
        }
    }

    impl<const KEY_LENGTH: usize, Nike: Debug + NIKE, Kdf: Debug + KDF<KEY_LENGTH>>
        std::error::Error for KemError<KEY_LENGTH, Nike, Kdf>
    where
        Nike::PublicKey: Debug,
    {
    }
}
