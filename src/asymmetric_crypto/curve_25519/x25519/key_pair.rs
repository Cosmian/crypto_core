use rand_core::CryptoRngCore;

use crate::{CryptoCoreError, RandomFixedSizeCBytes, X25519PrivateKey, X25519PublicKey};

/// An X25519 keypair which is compatible with the signature crate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct X25519Keypair {
    pub private_key: X25519PrivateKey,
    pub public_key: X25519PublicKey,
}

impl X25519Keypair {
    /// Generates a new random key pair.
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Result<Self, CryptoCoreError> {
        let private_key = X25519PrivateKey::new(rng);
        let public_key = X25519PublicKey::from(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }
}
