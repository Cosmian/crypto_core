use core::{
    fmt::Debug,
    ops::{Add, Div, Mul, Sub},
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{reexport::rand_core::CryptoRngCore, KeyTrait};

pub mod curve25519;

pub trait DhKeyPair<const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize>:
    Debug + PartialEq + Eq + Send + Sync + Sized + Clone + Zeroize + ZeroizeOnDrop
where
    Self::PublicKey: From<Self::PrivateKey>,
    for<'a, 'b> &'a Self::PublicKey: Add<&'b Self::PublicKey, Output = Self::PublicKey>
        + Mul<&'b Self::PrivateKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PrivateKey: Add<&'b Self::PrivateKey, Output = Self::PrivateKey>
        + Sub<&'b Self::PrivateKey, Output = Self::PrivateKey>
        + Mul<&'b Self::PrivateKey, Output = Self::PrivateKey>
        + Div<&'b Self::PrivateKey, Output = Self::PrivateKey>,
{
    /// This is needed to be able to use `{ MyKeyPair::PUBLIC_KEY_LENGTH }`
    /// as associated constant
    const PUBLIC_KEY_LENGTH: usize = PUBLIC_KEY_LENGTH;

    /// This is needed to be able to use `{ MyKeyPair::PRIVATE_KEY_LENGTH }`
    /// as associated constant
    const PRIVATE_KEY_LENGTH: usize = PRIVATE_KEY_LENGTH;

    /// Public key
    type PublicKey: KeyTrait<PUBLIC_KEY_LENGTH>;

    /// Private key
    type PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH>;

    /// Creates a new key pair
    #[must_use]
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self;

    /// Returns a reference to the public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Returns a reference to the private key.
    fn private_key(&self) -> &Self::PrivateKey;
}
