pub use ed25519_dalek::{SecretKey as EdSecretKey, VerifyingKey as EdPublicKey};

use crate::asymmetric_crypto::curve_25519::private_key::Curve25519PrivateKey;

pub type Ed25519PrivateKey = Curve25519PrivateKey;

impl TryFrom<&Ed25519PrivateKey> for EdSecretKey {
    type Error = crate::CryptoCoreError;

    fn try_from(sk: &Ed25519PrivateKey) -> Result<Self, Self::Error> {
        Ok(sk.0.to_bytes())
    }
}
