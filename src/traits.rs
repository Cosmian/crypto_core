use crate::{reexport::rand_core::CryptoRngCore, SymmetricKey};
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod kem_to_pke;

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
pub trait SecretCBytes<const LENGTH: usize>:
    FixedSizeCBytes<LENGTH> + Zeroize + ZeroizeOnDrop
{
}

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
    + Zero
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
    + One
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

/// A cyclic group is a group in which there exists a generator element g such
/// that for each element, there exists a multiplicity m such that this element
/// can be obtained by folding m instances of g with the group operation.
///
/// Noting m·g the operation of folding m instances of g, we have:
///
/// ∀ p ∈ G, ∃ m : p = m·g
///
/// By associativity of the group operation, a generated group is also an
/// abelian group.
pub trait CyclicGroup: AbelianGroup + One
where
    Self: From<Self::Multiplicity>,
    for<'a> Self: From<&'a Self::Multiplicity>,
    for<'a> &'a Self: Neg<Output = Self>,
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
    for<'a> &'a Self::Multiplicity: Neg<Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Add<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Sub<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Mul<&'b Self::Multiplicity, Output = Self::Multiplicity>,
    for<'a, 'b> &'a Self::Multiplicity: Div<
        &'b Self::Multiplicity,
        Output = Result<Self::Multiplicity, <Self::Multiplicity as Field>::InvError>,
    >,
{
    type Multiplicity: Field;
}

/// Authenticated encryption scheme.
pub trait AE<const KEY_LENGTH: usize> {
    type Plaintext;
    type Ciphertext;

    type Error: std::error::Error;

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

/// Key-Encapsulation Mechanism.
pub trait KEM<const KEY_LENGTH: usize> {
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
    ) -> Result<(SymmetricKey<KEY_LENGTH>, Self::Encapsulation), Self::Error>;

    /// Attempts opening the given encapsulation. Upon failure to decapsulate,
    /// returns a random session key.
    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error>;
}

/// Non-Interactive Key Exchange.
pub trait NIKE<const KEY_LENGTH: usize> {
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
    ) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error>;
}

/// Non-Interactive Key Exchange which public keys for a cyclic group.
pub trait KeyHomomorphicNike<const KEY_LENGTH: usize>: NIKE<KEY_LENGTH>
where
    Self::PublicKey: CyclicGroup<Multiplicity = Self::SecretKey>,
    Self::SecretKey: Field,
    for<'a> &'a Self::PublicKey: Neg<Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Add<&'b Self::PublicKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Sub<&'b Self::PublicKey, Output = Self::PublicKey>,
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

impl<const KEY_LENGTH: usize, T: NIKE<KEY_LENGTH>> KEM<KEY_LENGTH> for T {
    type Encapsulation = T::PublicKey;
    type EncapsulationKey = T::PublicKey;
    type DecapsulationKey = T::SecretKey;
    type Error = T::Error;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        T::keygen(rng)
    }

    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SymmetricKey<KEY_LENGTH>, Self::Encapsulation), Self::Error> {
        let (sk, pk) = T::keygen(rng)?;
        let ss = T::session_key(&sk, ek)?;
        Ok((ss, pk))
    }

    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error> {
        T::session_key(dk, enc)
    }
}

pub trait PKE {
    type Plaintext;
    type Ciphertext;
    type PublicKey;
    type SecretKey;
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

pub mod tests {
    use crate::{
        reexport::rand_core::SeedableRng,
        traits::{CyclicGroup, Field, KeyHomomorphicNike, Zero, KEM, NIKE},
        CsRng,
    };
    use std::ops::{Add, Div, Mul, Neg, Sub};

    /// A non-interactive key exchange must allow generating the same session key on
    /// both sides.
    pub fn test_nike<const KEY_LENGTH: usize, Scheme: NIKE<KEY_LENGTH>>() {
        let mut rng = CsRng::from_entropy();

        let keypair_1 = Scheme::keygen(&mut rng).unwrap();
        let keypair_2 = Scheme::keygen(&mut rng).unwrap();

        let session_key_1 = Scheme::session_key(&keypair_1.0, &keypair_2.1).unwrap();
        let session_key_2 = Scheme::session_key(&keypair_2.0, &keypair_1.1).unwrap();

        assert_eq!(session_key_1, session_key_2);
    }

    pub fn test_kem<const KEY_LENGTH: usize, Scheme: KEM<KEY_LENGTH>>() {
        let mut rng = CsRng::from_entropy();

        let (dk_1, ek_1) = Scheme::keygen(&mut rng).unwrap();
        let (dk_2, ek_2) = Scheme::keygen(&mut rng).unwrap();

        let (ss_1, enc_1) = Scheme::enc(&ek_1, &mut rng).unwrap();
        let (ss_2, enc_2) = Scheme::enc(&ek_2, &mut rng).unwrap();

        let ss_1_ = Scheme::dec(&dk_1, &enc_1).unwrap();
        let ss_2_ = Scheme::dec(&dk_2, &enc_2).unwrap();

        assert_eq!(ss_1, ss_1_);
        assert_eq!(ss_2, ss_2_);
    }

    pub fn test_homomorphic_nike<const KEY_LENGTH: usize, Scheme: KeyHomomorphicNike<KEY_LENGTH>>()
    where
        Scheme::PublicKey: CyclicGroup<Multiplicity = Scheme::SecretKey>,
        Scheme::SecretKey: Field,
        for<'a> &'a Scheme::PublicKey: Neg<Output = Scheme::PublicKey>,
        for<'a, 'b> &'a Scheme::PublicKey: Add<&'b Scheme::PublicKey, Output = Scheme::PublicKey>,
        for<'a, 'b> &'a Scheme::PublicKey: Sub<&'b Scheme::PublicKey, Output = Scheme::PublicKey>,
        for<'a> &'a Scheme::SecretKey: Neg<Output = Scheme::SecretKey>,
        for<'a, 'b> &'a Scheme::SecretKey: Add<&'b Scheme::SecretKey, Output = Scheme::SecretKey>,
        for<'a, 'b> &'a Scheme::SecretKey: Sub<&'b Scheme::SecretKey, Output = Scheme::SecretKey>,
        for<'a, 'b> &'a Scheme::SecretKey: Mul<&'b Scheme::SecretKey, Output = Scheme::SecretKey>,
        for<'a, 'b> &'a Scheme::SecretKey: Div<
            &'b Scheme::SecretKey,
            Output = Result<Scheme::SecretKey, <Scheme::SecretKey as Field>::InvError>,
        >,
    {
        // NOTE: test is performed via the KEM interface. Maybe use the NIKE
        // interface instead (may need to add more constraints,
        // e.g. Scheme::SessionKey = Scheme::PublicKey).

        let mut rng = CsRng::from_entropy();

        const N: usize = 10;

        let (sk, pk) = (0..N).map(|_| Scheme::keygen(&mut rng).unwrap()).fold(
            (Scheme::SecretKey::zero(), Scheme::PublicKey::zero()),
            |(sk, pk), (sk_i, pk_i)| (sk + sk_i, pk + pk_i),
        );

        let (ss, enc) = Scheme::enc(&pk, &mut rng).unwrap();
        let ss_ = Scheme::dec(&sk, &enc).unwrap();
        assert_eq!(ss, ss_);
    }
}

pub mod macros {
    #[macro_export]
    macro_rules! implement_monoid_arithmetic {
        ($type: ty) => {
            mod monoid_arithmetic {
                use super::*;
                use core::iter::Sum;

                impl Sum for $type {
                    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                        iter.fold(<Self as Monoid>::id(), |acc, e| {
                            <Self as Monoid>::op(&acc, &e)
                        })
                    }
                }

                impl<'a> Sum<&'a $type> for $type {
                    fn sum<I: Iterator<Item = &'a $type>>(iter: I) -> Self {
                        iter.fold(<Self as Monoid>::id(), |acc, e| {
                            <Self as Monoid>::op(&acc, e)
                        })
                    }
                }
            }
        };
    }

    /// Given a group, implements an Abelian group.
    #[macro_export]
    macro_rules! implement_abelian_group {
        ($type: ty) => {
            mod abelian_group_arithmetic {
                use super::*;
                use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

                impl Zero for $type {
                    fn zero() -> Self {
                        <Self as Monoid>::id()
                    }

                    fn is_zero(&self) -> bool {
                        self == &Self::zero()
                    }
                }

                impl Add for $type {
                    type Output = Self;

                    fn add(self, rhs: Self) -> Self::Output {
                        <$type as Monoid>::op(&self, &rhs)
                    }
                }

                impl Add<&$type> for $type {
                    type Output = $type;

                    fn add(self, rhs: &$type) -> Self::Output {
                        <$type as Monoid>::op(&self, &rhs)
                    }
                }

                impl Add<&$type> for &$type {
                    type Output = $type;

                    fn add(self, rhs: &$type) -> Self::Output {
                        <$type as Monoid>::op(&self, &rhs)
                    }
                }

                impl AddAssign for $type {
                    fn add_assign(&mut self, rhs: Self) {
                        *self = <$type as Monoid>::op(&self, &rhs)
                    }
                }

                impl Neg for $type {
                    type Output = Self;

                    fn neg(self) -> Self::Output {
                        <$type as Group>::invert(&self)
                    }
                }

                impl Neg for &$type {
                    type Output = $type;

                    fn neg(self) -> Self::Output {
                        <$type as Group>::invert(self)
                    }
                }

                impl Sub for $type {
                    type Output = Self;

                    fn sub(self, rhs: Self) -> Self::Output {
                        <$type as Monoid>::op(&self, &<$type as Group>::invert(&rhs))
                    }
                }

                impl Sub<&$type> for $type {
                    type Output = Self;

                    fn sub(self, rhs: &$type) -> Self::Output {
                        <$type as Monoid>::op(&self, &<$type as Group>::invert(&rhs))
                    }
                }

                impl Sub<&$type> for &$type {
                    type Output = $type;

                    fn sub(self, rhs: &$type) -> Self::Output {
                        <$type as Monoid>::op(&self, &<$type as Group>::invert(&rhs))
                    }
                }

                impl SubAssign for $type {
                    fn sub_assign(&mut self, rhs: Self) {
                        *self = <$type as Monoid>::op(&self, &<$type as Group>::invert(&rhs))
                    }
                }

                impl AbelianGroup for $type {}
            }
        };
    }

    /// Given a ring, implements a commutative ring (the ring operation is *).
    #[macro_export]
    macro_rules! implement_commutative_ring {
        ($type: ty) => {
            mod commutative_ring {
                use super::*;
                use std::ops::{Mul, MulAssign};

                impl One for $type {
                    fn one() -> Self {
                        <Self as Ring>::id()
                    }

                    fn is_one(&self) -> bool {
                        self == &Self::one()
                    }
                }

                impl Mul for $type {
                    type Output = Self;

                    fn mul(self, rhs: Self) -> Self::Output {
                        <$type as Ring>::op(&self, &rhs)
                    }
                }

                impl Mul<&$type> for $type {
                    type Output = $type;

                    fn mul(self, rhs: &$type) -> Self::Output {
                        <$type as Ring>::op(&self, &rhs)
                    }
                }

                impl Mul<&$type> for &$type {
                    type Output = $type;

                    fn mul(self, rhs: &$type) -> Self::Output {
                        <$type as Ring>::op(&self, &rhs)
                    }
                }

                impl MulAssign for $type {
                    fn mul_assign(&mut self, rhs: Self) {
                        *self = <$type as Ring>::op(&self, &rhs)
                    }
                }
            }
        };
    }
}
