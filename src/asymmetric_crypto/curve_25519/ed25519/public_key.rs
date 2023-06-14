//reexport the RustBox Ed25519 impl

use super::private_key::Ed25519PrivateKey;
use crate::{CBytes, FixedSizeCBytes};
pub use ed25519_dalek::{PublicKey as EdPublicKey, SecretKey as EdSecretKey};
use std::ops::Deref;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ed25519PublicKey(pub(crate) EdPublicKey);

impl CBytes for Ed25519PublicKey {}

impl FixedSizeCBytes<32> for Ed25519PublicKey {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(bytes: [u8; crypto_box::KEY_SIZE]) -> Result<Self, crate::CryptoCoreError> {
        Ok(Self(
            EdPublicKey::from_bytes(&bytes)
                .map_err(|_| crate::CryptoCoreError::InvalidBytesLength)?,
        ))
    }
}

impl TryFrom<&Ed25519PrivateKey> for Ed25519PublicKey {
    type Error = crate::CryptoCoreError;

    fn try_from(sk: &Ed25519PrivateKey) -> Result<Self, Self::Error> {
        Ok(Self(EdPublicKey::from(
            // TODO: creating the Secret key should never fail since the correct amount of bytes is provided.
            // TODO: It is unfortunate that the SecretKey field is private in ed25519.
            &EdSecretKey::from_bytes(sk.0.as_bytes())
                .map_err(|_| crate::CryptoCoreError::InvalidBytesLength)?,
        )))
    }
}

impl Deref for Ed25519PublicKey {
    type Target = EdPublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<Ed25519PublicKey> for EdPublicKey {
    fn from(val: Ed25519PublicKey) -> Self {
        val.0
    }
}
