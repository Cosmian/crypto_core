use std::ops::{Add, Div, Mul, Neg, Sub};

use crate::{
    bytes_ser_de::Serializable,
    reexport::{rand_core::CryptoRngCore, zeroize::ZeroizeOnDrop},
    traits::{CyclicGroup, Field, One, Sampling},
    Error, SymmetricKey,
};

pub mod cyclic_group_to_kem;
pub mod kem_combiner;
pub mod kem_to_pke;

/// Non-Interactive Key Exchange.
pub trait NIKE {
    type SecretKey: ZeroizeOnDrop;
    type PublicKey: Serializable;

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
    T::Element: ZeroizeOnDrop + Serializable,
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

    type Error = Error;

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
    T::Element: ZeroizeOnDrop + Serializable,
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
    type Encapsulation: PartialEq + Eq + Serializable;
    type EncapsulationKey: PartialEq + Eq + Serializable;
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
    type Ciphertext: PartialEq + Eq + Serializable;
    type PublicKey: Serializable;
    type SecretKey: ZeroizeOnDrop;
    type Error: std::error::Error;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error>;

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

pub trait Signature {
    type Signature: PartialEq + Eq + Serializable;
    type VerificationKey: Serializable;
    type SigningKey: ZeroizeOnDrop;
    type Error: std::error::Error;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), Self::Error>;

    fn sign(
        sk: &Self::SigningKey,
        msg: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Signature, Self::Error>;

    fn verify(
        sk: &Self::VerificationKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), Self::Error>;
}
