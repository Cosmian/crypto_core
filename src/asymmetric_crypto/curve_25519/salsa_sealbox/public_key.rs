use curve25519_dalek::MontgomeryPoint;
use rand_chacha::rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::KeyTrait;

pub const X25519_PUBLIC_KEY_LENGTH: usize = crypto_box::KEY_SIZE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(pub(crate) MontgomeryPoint);

impl KeyTrait<{ X25519_PUBLIC_KEY_LENGTH }> for X25519PublicKey {
    fn new<R: CryptoRngCore>(_rng: &mut R) -> Self {
        panic!("it does not make sense to construct a public key from arbitrary bytes")
    }

    fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(slice: &[u8]) -> Result<Self, crate::CryptoCoreError> {
        slice
            .try_into()
            .map(MontgomeryPoint)
            .map(Self)
            .map_err(|_| crate::CryptoCoreError::InvalidKeyLength)
    }
}

impl Zeroize for X25519PublicKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for X25519PublicKey {}
