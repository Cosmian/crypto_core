pub use ed25519_dalek::{PublicKey as EdPublicKey, SecretKey as EdSecretKey};

use crate::asymmetric_crypto::curve_25519::private_key::Curve25519PrivateKey;

pub type Ed25519PrivateKey = Curve25519PrivateKey;

impl TryInto<EdSecretKey> for Ed25519PrivateKey {
    type Error = crate::CryptoCoreError;

    fn try_into(self) -> Result<EdSecretKey, Self::Error> {
        EdSecretKey::from_bytes(self.0.as_bytes())
            .map_err(|_| crate::CryptoCoreError::InvalidBytesLength)
    }
}
