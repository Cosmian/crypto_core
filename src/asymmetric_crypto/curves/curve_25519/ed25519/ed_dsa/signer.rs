use ed25519_dalek::{ed25519, SigningKey};
pub use ed25519_dalek::{SecretKey as EdSecretKey, VerifyingKey as EdPublicKey};
use signature::Signer;

use crate::Ed25519PrivateKey;

/// Signer implementation for Ed25519.
///
/// This direct implementation involves a manipulations of the private key
/// and is therefore slower than the `CachedSigner` cached implementation when
/// signing multiple messages with the same key.
impl Signer<ed25519::Signature> for Ed25519PrivateKey {
    fn try_sign(&self, message: &[u8]) -> Result<ed25519::Signature, signature::Error> {
        let signing_key = SigningKey::from_bytes(&self.0);
        signing_key.try_sign(message)
    }
}

/// Cached signer implementation for Ed25519.
/// This implementation is faster than the direct implementation when signing
/// multiple messages with the same key.
///
/// The cached signer is created from an `Ed25519PrivateKey` using
/// `CachedSigner::try_from`.
pub struct Cached25519Signer(SigningKey);

impl TryFrom<&Ed25519PrivateKey> for Cached25519Signer {
    type Error = crate::CryptoCoreError;

    fn try_from(sk: &Ed25519PrivateKey) -> Result<Self, Self::Error> {
        let signing_key = SigningKey::from_bytes(&sk.0);
        Ok(Self(signing_key))
    }
}

impl Signer<ed25519::Signature> for Cached25519Signer {
    fn try_sign(&self, message: &[u8]) -> Result<ed25519::Signature, signature::Error> {
        self.0.try_sign(message)
    }
}
