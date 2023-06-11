use crate::asymmetric_crypto::curve_25519::ed25519::Ed25519PrivateKey;
use ed25519_dalek::{ed25519, ExpandedSecretKey};
pub use ed25519_dalek::{PublicKey as EdPublicKey, SecretKey as EdSecretKey};
use signature::Signer;

/// Signer implementation for Ed25519.
///
/// This direct implementation involves a manipulations of the private key
/// and is therefore slower than the CachedSigner cached implementation when
/// signing multiple messages with the same key.
impl Signer<ed25519::Signature> for Ed25519PrivateKey {
    fn try_sign(&self, message: &[u8]) -> Result<ed25519::Signature, signature::Error> {
        let sk: EdSecretKey = self
            .to_owned()
            .try_into()
            .map_err(|_| signature::Error::new())?;
        let public_key = EdPublicKey::from(&sk);
        let expanded: ExpandedSecretKey = (&sk).into();
        Ok(expanded.sign(message, &public_key))
    }
}

/// Cached signer implementation for Ed25519.
/// This implementation is faster than the direct implementation when signing
/// multiple messages with the same key.
///
/// The cached signer is created from an Ed25519PrivateKey using
/// `CachedSigner::try_from`.
pub struct Cached25519Signer {
    pk: EdPublicKey,
    expanded: ExpandedSecretKey,
}

impl TryFrom<&Ed25519PrivateKey> for Cached25519Signer {
    type Error = crate::CryptoCoreError;

    fn try_from(sk: &Ed25519PrivateKey) -> Result<Self, Self::Error> {
        let sk: EdSecretKey = sk
            .to_owned()
            .try_into()
            .map_err(|_| crate::CryptoCoreError::InvalidBytesLength)?;
        let pk = EdPublicKey::from(&sk);
        let expanded: ExpandedSecretKey = (&sk).into();
        Ok(Self { pk, expanded })
    }
}

impl Signer<ed25519::Signature> for Cached25519Signer {
    fn try_sign(&self, message: &[u8]) -> Result<ed25519::Signature, signature::Error> {
        Ok(self.expanded.sign(message, &self.pk))
    }
}
