use curve25519_dalek::{MontgomeryPoint, Scalar};
use rand_chacha::rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::KeyTrait;

use super::X25519PublicKey;

pub const X25519_PRIVATE_KEY_LENGTH: usize = crypto_box::KEY_SIZE;

#[derive(Clone, Debug)]
pub struct X25519PrivateKey(pub(crate) Scalar);

impl X25519PrivateKey {
    /// Derives the public key from the private key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(MontgomeryPoint::mul_base(&self.0))
    }
}

impl KeyTrait<{ X25519_PRIVATE_KEY_LENGTH }> for X25519PrivateKey {
    /// Generates a new private key.
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0; X25519_PRIVATE_KEY_LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(Scalar::from_bits_clamped(bytes))
    }

    fn to_bytes(&self) -> [u8; X25519_PRIVATE_KEY_LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(slice: &[u8]) -> Result<Self, crate::CryptoCoreError> {
        slice
            .try_into()
            .map(Scalar::from_bits_clamped)
            .map(Self)
            .map_err(|_| crate::CryptoCoreError::InvalidKeyLength)
    }
}

impl Zeroize for X25519PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for X25519PrivateKey {}

impl PartialEq for X25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for X25519PrivateKey {}
