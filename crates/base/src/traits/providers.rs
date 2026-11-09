use crate::traits::{AEAD_InPlace, CyclicGroup, Field, KEM};
use std::ops::{Add, Div, Mul, Neg, Sub};

/// Provider implementing AES256-GCM.
///
/// Note that this AEAD also implements an AE.
pub trait Aes256GcmProvider: AEAD_InPlace<32, 12, 16> {}

/// Provider implementing the Ristretto group of Curve25519.
///
/// Note that this cyclic group also implements a NIKE and that it is possible
/// to derive a KEM using the generic KEM implementation.
pub trait R25519GroupProvider: CyclicGroup
where
    for<'a> &'a Self::Element: Neg<Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Add<&'b Self::Element, Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Sub<&'b Self::Element, Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Mul<Self::Multiplicity, Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Mul<&'b Self::Multiplicity, Output = Self::Element>,
    for<'a> &'a Self::Multiplicity: Neg<Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Add<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Sub<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Mul<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Div<
        &'b Self::Multiplicity,
        Output = Result<Self::Multiplicity, <Self::Multiplicity as Field>::InvError>,
    >,
{
}

/// Provider implementing the cyclic group of the P256 NIST curve.
///
/// Note that this cyclic group also implements a NIKE and that it is possible
/// to derive a KEM using the generic KEM implementation.
pub trait P256GroupProvider: CyclicGroup
where
    for<'a> &'a Self::Element: Neg<Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Add<&'b Self::Element, Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Sub<&'b Self::Element, Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Mul<Self::Multiplicity, Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Mul<&'b Self::Multiplicity, Output = Self::Element>,
    for<'a> &'a Self::Multiplicity: Neg<Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Add<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Sub<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Mul<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Div<
        &'b Self::Multiplicity,
        Output = Result<Self::Multiplicity, <Self::Multiplicity as Field>::InvError>,
    >,
{
}

/// Provider implementing the cyclic group of the P384 NIST curve.
///
/// Note that this cyclic group also implements a NIKE and that it is possible
/// to derive a KEM using the generic KEM implementation.
pub trait P384GroupProvider: CyclicGroup
where
    for<'a> &'a Self::Element: Neg<Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Add<&'b Self::Element, Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Sub<&'b Self::Element, Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Mul<Self::Multiplicity, Output = Self::Element>,
    for<'a, 'b> &'a Self::Element: Mul<&'b Self::Multiplicity, Output = Self::Element>,
    for<'a> &'a Self::Multiplicity: Neg<Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Add<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Sub<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Mul<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Div<
        &'b Self::Multiplicity,
        Output = Result<Self::Multiplicity, <Self::Multiplicity as Field>::InvError>,
    >,
{
}

/// Provider implementing ML-KEM512.
pub trait MlKem512Provider: KEM<32> {}

/// Provider implementing ML-KEM512.
pub trait MlKem768Provider: KEM<32> {}
