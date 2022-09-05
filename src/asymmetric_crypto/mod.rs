use crate::KeyTrait;
use rand_core::{CryptoRng, RngCore};
use core::{
    fmt::Debug,
    ops::{Add, Mul},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod curve25519;

pub trait DhKeyPair<'a, const PK_LENGTH: usize, const SK_LENGTH: usize>:
    Debug + PartialEq + Eq + Send + Sync + Sized + Clone + Zeroize + ZeroizeOnDrop
where
    Self::PublicKey: Add + Mul<&'a Self::PrivateKey, Output = Self::PublicKey>,
    Self::PrivateKey: 'a + Add,
{
    /// Public key
    type PublicKey: KeyTrait<PK_LENGTH>;

    /// Secret key
    type PrivateKey: KeyTrait<SK_LENGTH>;

    /// Create a new key pair
    #[must_use]
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self;

    /// Return a reference to the public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Return a reference to the secret key.
    fn private_key(&self) -> &Self::PrivateKey;
}
