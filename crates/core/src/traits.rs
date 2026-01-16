use crate::{reexport::rand_core::CryptoRngCore, CryptoCoreError, Secret, SymmetricKey};
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::ZeroizeOnDrop;

pub mod cyclic_group_to_kem;
pub mod kem_to_pke;
pub mod macros;
pub mod providers;
pub mod tests;

// NOTE: the following four traits mirror those from `lib.rs` and should be
// those used in the end. In order to prevent a breaking change, their new
// version lives here for now.

/// Cryptographic bytes.
pub trait CBytes: Eq + PartialEq + Send + Sync {}

/// Fixed-size cryptographic bytes.
pub trait FixedSizeCBytes<const LENGTH: usize>: CBytes + Sized {
    /// Key length.
    const LENGTH: usize = LENGTH;
}

/// Fixed-size cryptographic secret bytes.
pub trait SecretCBytes<const LENGTH: usize>: FixedSizeCBytes<LENGTH> + ZeroizeOnDrop {}

// END NOTE //

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

/// Key Derivation Function.
pub trait KDF<const KEY_LENGTH: usize> {
    fn derive(seed: &[u8], info: &[u8]) -> SymmetricKey<KEY_LENGTH>;
}

/// Authenticated Encryption scheme.
pub trait AE<const KEY_LENGTH: usize> {
    type Plaintext;
    type Ciphertext;

    type Error: std::error::Error;

    /// The length of the key.
    const KEY_LENGTH: usize = KEY_LENGTH;

    /// Encrypts the given plaintext using the given key.
    fn encrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
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

/// Authenticated Encryption scheme with Associated Data.
pub trait AEAD<const KEY_LENGTH: usize> {
    type Plaintext;
    type Ciphertext;

    type Error: std::error::Error;

    /// The length of the key.
    const KEY_LENGTH: usize = KEY_LENGTH;

    /// Encrypts the given plaintext using the given key and associated data.
    fn encrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
        ad: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Ciphertext, Self::Error>;

    /// Decrypts the given ciphertext using the given key and associated data.
    ///
    /// # Error
    ///
    /// Returns an error if the integrity of the ciphertext could not be verified.
    fn decrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ctx: &Self::Ciphertext,
        ad: &[u8],
    ) -> Result<Self::Plaintext, Self::Error>;
}

// An AEAD trivially implements an AE.
impl<const KEY_LENGTH: usize, Aead: AEAD<KEY_LENGTH>> AE<KEY_LENGTH> for Aead {
    type Plaintext = Aead::Plaintext;

    type Ciphertext = Aead::Ciphertext;

    type Error = Aead::Error;

    fn encrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ptx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Ciphertext, Self::Error> {
        Aead::encrypt(key, ptx, b"", rng)
    }

    fn decrypt(
        key: &SymmetricKey<KEY_LENGTH>,
        ctx: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Self::Error> {
        Aead::decrypt(key, ctx, b"")
    }
}

/// Non-Interactive Key Exchange.
pub trait NIKE {
    type SecretKey: ZeroizeOnDrop;
    type PublicKey;

    /// The shared secret is not always a symmetric key, as such it is not
    /// required to be uniformly-random over its domain and is not always
    /// suitable to use as a symmetric key. However, provided it contains enough
    /// entropy, it is suitable to use as a KDF seed.
    type SharedSecret: ZeroizeOnDrop;

    type Error: std::error::Error;

    /// Generates a new random keypair.
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error>;

    /// Generates the shared secret associated to the given keypair.
    fn shared_secret(
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, Self::Error>;
}

// A cyclic group trivially implements a NIKE.
impl<T: CyclicGroup> NIKE for T
where
    T::Element: ZeroizeOnDrop,
    T::Multiplicity: Sampling + ZeroizeOnDrop,
    for<'a> &'a T::Element: Neg<Output = T::Element>,
    for<'a, 'b> &'a T::Element: Add<&'b T::Element, Output = T::Element>,
    for<'a, 'b> &'a T::Element: Sub<&'b T::Element, Output = T::Element>,
    for<'a, 'b> &'a T::Element: Mul<T::Multiplicity, Output = T::Element>,
    for<'a, 'b> &'a T::Element: Mul<&'b T::Multiplicity, Output = T::Element>,
    for<'a> &'a T::Multiplicity: Neg<Output = T::Multiplicity>,
    for<'a, 'b> &'a T::Multiplicity: Add<&'b T::Multiplicity, Output = T::Multiplicity>,
    for<'a, 'b> &'a T::Multiplicity: Sub<&'b T::Multiplicity, Output = T::Multiplicity>,
    for<'a, 'b> &'a T::Multiplicity: Mul<&'b T::Multiplicity, Output = T::Multiplicity>,
    for<'a, 'b> &'a T::Multiplicity: Div<
        &'b T::Multiplicity,
        Output = Result<T::Multiplicity, <T::Multiplicity as Field>::InvError>,
    >,
{
    type SecretKey = T::Multiplicity;

    type PublicKey = T::Element;

    type SharedSecret = T::Element;

    type Error = CryptoCoreError;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error> {
        let sk = T::Multiplicity::random(rng);
        let pk = T::Element::one() * &sk;
        Ok((sk, pk))
    }

    fn shared_secret(
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, Self::Error> {
        Ok(pk * sk)
    }
}

/// Non-Interactive Key Exchange which public keys for a cyclic group.
pub trait KeyHomomorphicNike:
    CyclicGroup
    + NIKE<SecretKey = Self::Multiplicity, PublicKey = Self::Element, SharedSecret = Self::Element>
where
    for<'a> &'a Self::PublicKey: Neg<Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Add<&'b Self::PublicKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Sub<&'b Self::PublicKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Mul<Self::SecretKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Mul<&'b Self::SecretKey, Output = Self::PublicKey>,
    for<'a> &'a Self::SecretKey: Neg<Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Add<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Sub<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Mul<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Div<
        &'b Self::SecretKey,
        Output = Result<Self::SecretKey, <Self::SecretKey as Field>::InvError>,
    >,
{
}

// A cyclic group trivially implements a key-homomorphic NIKE.
impl<T: CyclicGroup> KeyHomomorphicNike for T
where
    T::Element: ZeroizeOnDrop,
    T::Multiplicity: Sampling + ZeroizeOnDrop,
    for<'a> &'a T::Element: Neg<Output = T::Element>,
    for<'a, 'b> &'a T::Element: Add<&'b T::Element, Output = T::Element>,
    for<'a, 'b> &'a T::Element: Sub<&'b T::Element, Output = T::Element>,
    for<'a, 'b> &'a T::Element: Mul<T::Multiplicity, Output = T::Element>,
    for<'a, 'b> &'a T::Element: Mul<&'b T::Multiplicity, Output = T::Element>,
    for<'a> &'a T::Multiplicity: Neg<Output = T::Multiplicity>,
    for<'a, 'b> &'a T::Multiplicity: Add<&'b T::Multiplicity, Output = T::Multiplicity>,
    for<'a, 'b> &'a T::Multiplicity: Sub<&'b T::Multiplicity, Output = T::Multiplicity>,
    for<'a, 'b> &'a T::Multiplicity: Mul<&'b T::Multiplicity, Output = T::Multiplicity>,
    for<'a, 'b> &'a T::Multiplicity: Div<
        &'b T::Multiplicity,
        Output = Result<T::Multiplicity, <T::Multiplicity as Field>::InvError>,
    >,
{
}

/// Key-Encapsulation Mechanism.
pub trait KEM<const KEY_LENGTH: usize> {
    type Encapsulation;
    type EncapsulationKey;
    type DecapsulationKey: ZeroizeOnDrop;

    type Error: std::error::Error;

    /// The length of the encapsulated session key.
    const KEY_LENGTH: usize = KEY_LENGTH;

    /// Generates a new random keypair.
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error>;

    /// Generates an encapsulation of a random session key, and returns both the
    /// key and its encapsulation.
    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SymmetricKey<KEY_LENGTH>, Self::Encapsulation), Self::Error>;

    /// Attempts opening the given encapsulation. Upon failure to decapsulate,
    /// returns a random session key.
    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error>;
}

/// Public-Key Encryption.
pub trait PKE {
    type Plaintext;
    type Ciphertext;
    type PublicKey;
    type SecretKey: ZeroizeOnDrop;
    type Error;

    fn encrypt(
        pk: &Self::PublicKey,
        ptx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Ciphertext, Self::Error>;

    fn decrypt(
        sk: &Self::SecretKey,
        ctx: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Self::Error>;
}
