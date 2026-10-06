use crate::{reexport::rand_core::CryptoRngCore, Secret};
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::ZeroizeOnDrop;

mod asymmetric;
mod symmetric;

pub use asymmetric::*;
pub use symmetric::*;

pub mod macros;
pub mod providers;
pub mod tests;

/// Fixed-size cryptographic bytes.
pub trait FixedSizeCBytes<const LENGTH: usize>: Sized {
    const LENGTH: usize = LENGTH;

    type Error: std::error::Error;

    fn write(&self, buf: &mut [u8; LENGTH]) -> Result<(), Self::Error>;
    fn read(buf: &[u8; LENGTH]) -> Result<Self, Self::Error>;
}

/// Fixed-size cryptographic secret bytes.
pub trait SecretCBytes<const LENGTH: usize>: FixedSizeCBytes<LENGTH> + ZeroizeOnDrop {}

pub trait Sampling {
    /// Returns a fresh uniformly-random element.
    fn random(rng: &mut impl CryptoRngCore) -> Self;
}

pub trait Seedable<const LENGTH: usize> {
    /// Returns a fresh element deterministically computed from the given seed.
    fn from_seed(seed: &Secret<LENGTH>) -> Self;
}

pub trait Zero {
    fn zero() -> Self;
    fn is_zero(&self) -> bool;
}

pub trait One {
    fn one() -> Self;
    fn is_one(&self) -> bool;
}

/// A monoid is a set of elements endowed with an associative binary operation
/// for which there exists a neutral element in this group.
pub trait Monoid: Sized + Eq + PartialEq {
    /// Neutral element.
    fn id() -> Self;
    /// Monoidal operation.
    fn op(&self, rhs: &Self) -> Self;
}

/// A group is a set of elements endowed with a binary operation for which there
/// exists a neutral element in this group and for which each element has an
/// inverse.
pub trait Group: Monoid {
    fn invert(&self) -> Self;
}

/// An Abelian group is a group which operation is commutative.
///
/// We therefore use the standard + and - to represent the group operation and
/// inversion.
pub trait AbelianGroup:
    Group
    + Add<Output = Self>
    + AddAssign
    + Neg
    + Sub<Output = Self>
    + SubAssign
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
where
    for<'a> &'a Self: Neg<Output = Self>,
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
{
}

// In an Abelian group, the neutral element is associated to 0.
impl<T: AbelianGroup> Zero for T
where
    for<'a> &'a Self: Neg<Output = Self>,
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
{
    fn zero() -> Self {
        <Self as Monoid>::id()
    }

    fn is_zero(&self) -> bool {
        self == &Self::zero()
    }
}

/// A ring is an Abelian group endowed with a monoidal operation that
/// distributes over the group operation.
pub trait Ring: AbelianGroup
where
    for<'a> &'a Self: Neg<Output = Self>,
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
{
    fn id() -> Self;
    fn op(&self, rhs: &Self) -> Self;
}

/// A field is a set of elements endowed with two binary operations (+ and *),
/// such that it is an Abelian group for the addition, and its non-zero elements
/// form an Abelian group for the multiplication.
pub trait Field:
    Ring
    + Neg<Output = Self>
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Result<Self, Self::InvError>>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Result<Self, Self::InvError>>
where
    for<'a> &'a Self: Neg<Output = Self>,
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Mul<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Div<&'b Self, Output = Result<Self, Self::InvError>>,
{
    /// Error thrown by the inversion for the multiplicative law.
    type InvError: std::error::Error;

    /// Inverse operation for the multiplicative law.
    fn invert(&self) -> Result<Self, Self::InvError>;
}

// In a field, the neutral element for the multiplicative operation is
// associated to 1.
impl<T: Field> One for T
where
    for<'a> &'a Self: Neg<Output = Self>,
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Mul<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Div<&'b Self, Output = Result<Self, <Self as Field>::InvError>>,
{
    fn one() -> Self {
        <Self as Ring>::id()
    }

    fn is_one(&self) -> bool {
        self == &Self::one()
    }
}

/// A cyclic group is a group in which there exists a generator element g such
/// that: for each element, there exists a multiplicity m such that this element
/// can be obtained by folding m instances of g with the group operation.
///
/// Noting m·g the operation of folding m instances of g, we have:
///
/// ∀ p ∈ G, ∃ m : p = m·g
///
/// By associativity of the group operation, a generated group is also an
/// Abelian group.
pub trait CyclicGroup
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
    type Element: AbelianGroup
        + One
        + From<Self::Multiplicity>
        + for<'a> From<&'a Self::Multiplicity>
        + Mul<Self::Multiplicity, Output = Self::Element>
        + for<'a> Mul<&'a Self::Multiplicity, Output = Self::Element>;
    type Multiplicity: Field;
}
