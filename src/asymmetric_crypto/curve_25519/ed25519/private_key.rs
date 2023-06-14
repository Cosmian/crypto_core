pub use ed25519_dalek::{PublicKey as EdPublicKey, SecretKey as EdSecretKey};

use crate::asymmetric_crypto::curve_25519::private_key::Curve25519PrivateKey;

pub type Ed25519PrivateKey = Curve25519PrivateKey;

impl TryFrom<&Ed25519PrivateKey> for EdSecretKey {
    type Error = crate::CryptoCoreError;

    fn try_from(sk: &Ed25519PrivateKey) -> Result<Self, Self::Error> {
        EdSecretKey::from_bytes(sk.0.as_bytes())
            .map_err(|_| crate::CryptoCoreError::InvalidBytesLength)
    }
}
