use crate::{reexport::rand_core::CryptoRngCore, SymmetricKey};
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Sub, SubAssign};

pub trait Sampling {
    /// Returns a fresh uniformly-random element.
    fn random(rng: &mut impl CryptoRngCore) -> Self;
}

pub trait Seedable<const LENGTH: usize> {
    /// Returns a fresh element deterministically computed from the given seed.
    fn from_seed(seed: &[u8; LENGTH]) -> Self;
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
pub trait Monoid: Sized {
    /// Neutral element.
    fn e() -> Self;
    /// Monoidal operation.
    fn op(&self, rhs: &Self) -> Self;
}

/// A group is a set of elements endowed with a binary operation for which there
/// exists a neutral element in this group and for which each element has an
/// inverse.
pub trait Group: Sized {
    fn e() -> Self;
    fn inverse(&self) -> Self;
    fn op(&self, rhs: &Self) -> Self;
}

/// An Abelian group is which operation is commutative.
///
/// We therefore use the standard + and - to represent the group operation and
/// inversion.
pub trait AbelianGroup:
    Group
    + Zero
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
where
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
{
}

/// A ring is an Abelian group endowed with a monoidal operation that
/// distributes over the group operation.
pub trait Ring: AbelianGroup + Monoid
where
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
{
}

/// A field is a set of elements endowed with two binary operations (+ and *),
/// such that it is an Abelian group for the addition, and its non-zero elements
/// form an Abelian group for the multiplication.
pub trait Field:
    Ring
    + One
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Result<Self, Self::InvError>>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Result<Self, Self::InvError>>
where
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Mul<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Div<&'b Self, Output = Result<Self, Self::InvError>>,
{
    /// Error thrown by the inversion for the multiplicative law.
    type InvError;

    /// Inverse operation for the multiplicative law.
    fn inverse(&self) -> Result<Self, Self::InvError>;
}

pub trait GeneratedGroup: Group + One
where
    for<'a, 'b> &'a Self::Scalar: Add<&'b Self::Scalar, Output = Self::Scalar>,
    for<'a, 'b> &'a Self::Scalar: Sub<&'b Self::Scalar, Output = Self::Scalar>,
    for<'a, 'b> &'a Self::Scalar: Mul<&'b Self::Scalar, Output = Self::Scalar>,
    for<'a, 'b> &'a Self::Scalar:
        Div<&'b Self::Scalar, Output = Result<Self::Scalar, <Self::Scalar as Field>::InvError>>,
{
    type Scalar: Field;
}

pub trait AE<const KEY_LENGTH: usize> {
    type Key;
    type Plaintext;
    type Ciphertext;
    type Error: std::error::Error;

    /// Encrypts the given plaintext using the given key.
    fn encrypt(
        key: &Self::Key,
        ptx: &Self::Plaintext,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Ciphertext, Self::Error>;

    /// Decrypts the given ciphertext using the given key.
    ///
    /// # Error
    ///
    /// Returns an error if the integrity of the ciphertext could not be verified.
    fn decrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ctx: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Self::Error>;
}

pub trait Kem {
    type SessionKey;
    type Encapsulation;
    type EncapsulationKey;
    type DecapsulationKey;
    type Error: std::error::Error;

    /// Generates a new random keypair.
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error>;

    /// Generates an encapsulation of a random session key, and returns both the
    /// key and its encapsulation.
    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SessionKey, Self::Encapsulation), Self::Error>;

    /// Attempts opening the given encapsulation. Upon failure to decapsulate,
    /// returns a random session key.
    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Self::SessionKey, Self::Error>;
}

pub trait Nike {
    type SessionKey;
    type SecretKey;
    type PublicKey;
    type Error: std::error::Error;

    /// Generates a new random keypair.
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error>;

    /// Generates the session key associated to the given keypair.
    fn session_key(
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Result<Self::SessionKey, Self::Error>;
}

pub trait KeyHomomorphicNike: Nike
where
    Self::PublicKey: GeneratedGroup<Scalar = Self::SecretKey>,
    Self::SecretKey: Field,
    for<'a, 'b> &'a Self::SecretKey: Add<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Sub<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Mul<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Div<
        &'b Self::SecretKey,
        Output = Result<Self::SecretKey, <Self::SecretKey as Field>::InvError>,
    >,
{
}
