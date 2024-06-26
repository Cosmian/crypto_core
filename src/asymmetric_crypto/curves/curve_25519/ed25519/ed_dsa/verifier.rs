use ed25519_dalek::ed25519;
use signature::Verifier;

use crate::Ed25519PublicKey;

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
