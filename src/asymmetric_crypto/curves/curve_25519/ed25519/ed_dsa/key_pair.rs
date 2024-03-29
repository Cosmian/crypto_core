use signature::{Keypair, Signer, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    asymmetric_crypto::{Ed25519PrivateKey, Ed25519PublicKey},
    reexport::rand_core::CryptoRngCore,
    CBytes, CryptoCoreError, FixedSizeCBytes,
};

/// An Ed25519 keypair which is compatible with the signature crate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ed25519Keypair {
    pub private_key: Ed25519PrivateKey,
    pub public_key: Ed25519PublicKey,
}

impl Keypair for Ed25519Keypair {
    type VerifyingKey = Ed25519PublicKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.public_key.clone()
    }
}

pub struct Ed25519Signature {
    pub(crate) signature: ed25519_dalek::Signature,
}
impl Ed25519Signature {
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.signature.to_vec()
    }
}

impl Signer<Ed25519Signature> for Ed25519Keypair {
    fn try_sign(&self, message: &[u8]) -> Result<Ed25519Signature, signature::Error> {
        Ok(Ed25519Signature {
            signature: self.private_key.try_sign(message)?,
        })
    }
}
impl Verifier<Ed25519Signature> for Ed25519Keypair {
    fn verify(&self, msg: &[u8], signature: &Ed25519Signature) -> Result<(), signature::Error> {
        self.public_key.verify(msg, &signature.signature)
    }
}

impl CBytes for Ed25519Keypair {}

impl FixedSizeCBytes<{ Ed25519PrivateKey::LENGTH + Ed25519PublicKey::LENGTH }> for Ed25519Keypair {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        let mut bytes = [0; Self::LENGTH];
        bytes[..Ed25519PrivateKey::LENGTH].copy_from_slice(self.private_key.as_bytes());
        bytes[Ed25519PrivateKey::LENGTH..].copy_from_slice(self.public_key.as_bytes());
        bytes
    }

    fn try_from_bytes(bytes: [u8; Self::LENGTH]) -> Result<Self, crate::CryptoCoreError> {
        let private_key = Ed25519PrivateKey::try_from_bytes(
            bytes[..Ed25519PrivateKey::LENGTH].try_into().map_err(|_| {
                crate::CryptoCoreError::InvalidBytesLength(
                    "key pair (private key)".to_string(),
                    Ed25519PrivateKey::LENGTH,
                    None,
                )
            })?,
        )?;
        let public_key = Ed25519PublicKey::try_from_bytes(
            bytes[Ed25519PrivateKey::LENGTH..].try_into().map_err(|_| {
                crate::CryptoCoreError::InvalidBytesLength(
                    "key pair (public key)".to_string(),
                    Ed25519PrivateKey::LENGTH,
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

impl Zeroize for Ed25519Keypair {
    fn zeroize(&mut self) {
        self.private_key.zeroize();
    }
}

impl Drop for Ed25519Keypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Ed25519Keypair {}

impl Ed25519Keypair {
    /// Generates a new random key pair.
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Result<Self, CryptoCoreError> {
        let private_key = Ed25519PrivateKey::new(rng);
        let public_key = Ed25519PublicKey::from(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }
}
