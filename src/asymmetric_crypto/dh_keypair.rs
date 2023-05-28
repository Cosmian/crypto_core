use crate::reexport::rand_core::CryptoRngCore;
use core::{
    fmt::Debug,
    ops::{Add, Div, Mul, Sub},
};

use zeroize::{Zeroize, ZeroizeOnDrop};
pub trait DhKeyPair<PrivateKey, PublicKey>:
    Debug + PartialEq + Eq + Send + Sync + Sized + Clone + Zeroize + ZeroizeOnDrop
where
    PublicKey: From<PrivateKey>,
    for<'a, 'b> &'a PublicKey:
        Add<&'b PublicKey, Output = PublicKey> + Mul<&'b PrivateKey, Output = PublicKey>,
    for<'a, 'b> &'a PrivateKey: Add<&'b PrivateKey, Output = PrivateKey>
        + Sub<&'b PrivateKey, Output = PrivateKey>
        + Mul<&'b PrivateKey, Output = PrivateKey>
        + Div<&'b PrivateKey, Output = PrivateKey>,
{
    /// Creates a new key pair
    #[must_use]
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self;

    /// Returns a reference to the public key.
    fn public_key(&self) -> &PublicKey;

    /// Returns a reference to the private key.
    fn private_key(&self) -> &PrivateKey;
}
