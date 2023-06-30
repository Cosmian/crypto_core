use ed25519_dalek::ed25519;
pub use ed25519_dalek::{SecretKey as EdSecretKey, VerifyingKey as EdPublicKey};
use signature::Verifier;

use crate::asymmetric_crypto::curve_25519::ed25519::Ed25519PublicKey;

/// Verifier implementation for Ed25519.
impl Verifier<ed25519::Signature> for Ed25519PublicKey {
    fn verify(
        &self,
        message: &[u8],
        signature: &ed25519::Signature,
    ) -> Result<(), signature::Error> {
        self.0
            .verify(message, signature)
            .map_err(|_| signature::Error::new())
    }
}
