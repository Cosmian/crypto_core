use rand_core::CryptoRngCore;

use crate::{
    CBytes, CryptoCoreError, FixedSizeCBytes, RandomFixedSizeCBytes, X25519PrivateKey,
    X25519PublicKey,
};

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

impl FixedSizeCBytes<{ X25519PrivateKey::LENGTH + X25519PublicKey::LENGTH }> for X25519Keypair {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        let mut bytes = [0; Self::LENGTH];
        bytes[..X25519PrivateKey::LENGTH].copy_from_slice(self.private_key.as_bytes());
        bytes[X25519PrivateKey::LENGTH..].copy_from_slice(self.public_key.as_bytes());
        bytes
    }

    fn try_from_bytes(bytes: [u8; Self::LENGTH]) -> Result<Self, crate::CryptoCoreError> {
        let private_key = X25519PrivateKey::try_from_bytes(
            bytes[..X25519PrivateKey::LENGTH].try_into().map_err(|_| {
                crate::CryptoCoreError::InvalidBytesLength(
                    "key pair (private key)".to_string(),
                    X25519PrivateKey::LENGTH,
                    None,
                )
            })?,
        )?;
        let public_key = X25519PublicKey::try_from_bytes(
            bytes[X25519PrivateKey::LENGTH..].try_into().map_err(|_| {
                crate::CryptoCoreError::InvalidBytesLength(
                    "key pair (public key)".to_string(),
                    X25519PrivateKey::LENGTH,
                    None,
                )
            })?,
        )?;
        Ok(Self {
            private_key,
            public_key,
        })
    }
}
impl CBytes for X25519Keypair {}
