use sha2::{Digest, Sha512};

use crate::{
    asymmetric_crypto::curve_25519::curve_secret::Curve25519Secret, Ed25519PrivateKey,
    CURVE_25519_SECRET_LENGTH,
};

pub type X25519PrivateKey = Curve25519Secret;

impl X25519PrivateKey {
    /// Convert the ED25519 private key to an X25519 private key
    ///
    /// This method is useful when an Ed25519 public key has been converted to
    /// an X25519 public key. It will generate the private key that
    /// corresponds to the generated X25519 public key from the original
    /// private key.
    ///
    /// See [`X25519PublicKey::from_ed25519_public_key`] for more details.
    pub fn from_ed25519_private_key(sk: &Ed25519PrivateKey) -> Self {
        // see ed25519_dalek::ExpandedSecretKey::to_curve25519_private_key
        // The spec-compliant way to define an expanded secret key. This computes
        // `SHA512(sk)`, clamps the first 32 bytes and uses it as a scalar, and
        // uses the second 32 bytes as a domain separator for hashing.
        // We recover the same first 32 bytes to generate the scalar for X25519
        let hash = Sha512::default().chain_update(sk.as_bytes()).finalize();
        let mut seed = [0_u8; CURVE_25519_SECRET_LENGTH];
        seed.copy_from_slice(&hash[0..CURVE_25519_SECRET_LENGTH]);
        Self(seed)
    }
}

impl From<&Ed25519PrivateKey> for X25519PrivateKey {
    fn from(sk: &Ed25519PrivateKey) -> Self {
        Self::from_ed25519_private_key(sk)
    }
}
