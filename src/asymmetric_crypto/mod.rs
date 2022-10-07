use crate::KeyTrait;
use core::{
    fmt::Debug,
    ops::{Add, Div, Mul, Sub},
};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod curve25519;

pub trait DhKeyPair<const PK_LENGTH: usize, const SK_LENGTH: usize>:
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
    /// This is needed to be able to use `{ MyKeyPair::PK_LENGTH }`
    /// as associated constant
    const PK_LENGTH: usize = PK_LENGTH;

    /// This is needed to be able to use `{ MyKeyPair::SK_LENGTH }`
    /// as associated constant
    const SK_LENGTH: usize = SK_LENGTH;

    /// Public key
    type PublicKey: KeyTrait<PK_LENGTH>;

    /// Secret key
    type PrivateKey: KeyTrait<SK_LENGTH>;

    /// Creates a new key pair
    #[must_use]
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self;

    /// Returns a reference to the public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Returns a reference to the secret key.
    fn private_key(&self) -> &Self::PrivateKey;
}
