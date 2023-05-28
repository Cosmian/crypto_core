use curve25519_dalek::RistrettoPoint;

use crate::asymmetric_crypto::curve_25519::private_key::Curve25519PrivateKey;

use super::R25519PublicKey;

pub type R25519PrivateKey = Curve25519PrivateKey;

impl R25519PrivateKey {
    /// Derives the public key from the private key.
    #[must_use]
    pub fn r25519_public_key(&self) -> R25519PublicKey {
        R25519PublicKey(RistrettoPoint::mul_base(&self.0))
    }
}
