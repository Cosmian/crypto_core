//reexport the RustBox Ed25519 impl

//! Edwards Digital Signature Algorithm (EdDSA) over Curve25519 as specified in RFC 8032.
//! https://tools.ietf.org/html/rfc8032

use super::{private_key::Ed25519PrivateKey, Ed25519PublicKey};
use ed25519_dalek::{ed25519, ExpandedSecretKey, Verifier as DalekVerifier};
pub use ed25519_dalek::{PublicKey as EdPublicKey, SecretKey as EdSecretKey};
use signature::{Signer, Verifier};

impl Signer<ed25519::Signature> for Ed25519PrivateKey {
    fn try_sign(&self, message: &[u8]) -> Result<ed25519::Signature, signature::Error> {
        let sk: EdSecretKey = self
            .to_owned()
            .try_into()
            .map_err(|_| signature::Error::new())?;
        let public_key = EdPublicKey::from(&sk);
        let expanded: ExpandedSecretKey = (&sk).into();
        Ok(expanded.sign(&message, &public_key).into())
    }
}

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

#[cfg(test)]
mod tests {

    use crate::asymmetric_crypto::curve_25519::ed_25519::Ed25519PrivateKey;
    use crate::asymmetric_crypto::curve_25519::ed_25519::Ed25519PublicKey;
    use crate::reexport::rand_core::SeedableRng;
    use crate::SecretKey;
    use signature::Signer;
    use signature::Verifier;

    use crate::CsRng;

    #[test]
    fn ed25519_test() {
        let mut rng = CsRng::from_entropy();
        let message = b"Hello, world!";

        // sign the message
        let private_key = Ed25519PrivateKey::new(&mut rng);
        let signature = private_key.try_sign(message).unwrap();

        // verify the signature
        let public_key = Ed25519PublicKey::from(&private_key);
        public_key.verify(message, &signature).unwrap();
    }
}
