use super::X25519PublicKey;
use crate::asymmetric_crypto::curve_25519::private_key::Curve25519PrivateKey;
use curve25519_dalek::MontgomeryPoint;

pub type X25519PrivateKey = Curve25519PrivateKey;

impl X25519PrivateKey {
    /// Derives the public key from the private key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(MontgomeryPoint::mul_base(&self.0))
    }
}
