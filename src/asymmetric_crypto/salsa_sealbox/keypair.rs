use crypto_box::{PublicKey, SecretKey};
use rand_chacha::rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::KeyTrait;

pub const X25519_PRIVATE_KEY_LENGTH: usize = crypto_box::KEY_SIZE;
pub const X25519_PUBLIC_KEY_LENGTH: usize = crypto_box::KEY_SIZE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(pub(crate) PublicKey);

impl KeyTrait<{ X25519_PUBLIC_KEY_LENGTH }> for X25519PublicKey {
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut buffer = [0; X25519_PUBLIC_KEY_LENGTH];
        rng.fill_bytes(&mut buffer);
        Self(PublicKey::from(buffer))
    }

    fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoCoreError> {
        PublicKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| crate::CryptoCoreError::InvalidKeyLength)
    }
}

impl Zeroize for X25519PublicKey {
    fn zeroize(&mut self) {
        self.0 = PublicKey::from_bytes([0; X25519_PUBLIC_KEY_LENGTH]);
    }
}

impl ZeroizeOnDrop for X25519PublicKey {}

#[derive(Clone, Debug)]
pub struct X25519PrivateKey(pub(crate) SecretKey);

impl X25519PrivateKey {
    /// Derives the public key from the private key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(self.0.public_key())
    }
}

impl KeyTrait<{ X25519_PRIVATE_KEY_LENGTH }> for X25519PrivateKey {
    /// Generates a new private key.
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self(SecretKey::generate(rng))
    }

    fn to_bytes(&self) -> [u8; X25519_PRIVATE_KEY_LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoCoreError> {
        SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| crate::CryptoCoreError::InvalidKeyLength)
    }
}

impl Zeroize for X25519PrivateKey {
    fn zeroize(&mut self) {
        self.0 = SecretKey::from_bytes([0; X25519_PRIVATE_KEY_LENGTH]);
    }
}

impl ZeroizeOnDrop for X25519PrivateKey {}

impl PartialEq for X25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for X25519PrivateKey {}
