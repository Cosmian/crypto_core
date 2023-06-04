//reexport the RustBox Ed25519 impl

use super::private_key::Ed25519PrivateKey;
use crate::{FixedSizeKey, Key};
pub use ed25519_dalek::{PublicKey as EdPublicKey, SecretKey as EdSecretKey};
use std::ops::Deref;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ed25519PublicKey(pub(crate) EdPublicKey);

impl Key for Ed25519PublicKey {}

impl FixedSizeKey<32> for Ed25519PublicKey {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(bytes: [u8; crypto_box::KEY_SIZE]) -> Result<Self, crate::CryptoCoreError> {
        Ok(Self(
            EdPublicKey::from_bytes(&bytes)
                .map_err(|_| crate::CryptoCoreError::InvalidKeyLength)?,
        ))
    }
}

impl From<&Ed25519PrivateKey> for Ed25519PublicKey {
    fn from(sk: &Ed25519PrivateKey) -> Self {
        Self(EdPublicKey::from(&EdSecretKey::from_bytes(sk.0.as_bytes()).expect("creating the Secret key should never fail since the correct amount of bytes is provided. It is unfortunate that the SecretKey field is private in ed25519.")))
    }
}

impl Deref for Ed25519PublicKey {
    type Target = EdPublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Into<EdPublicKey> for Ed25519PublicKey {
    fn into(self) -> EdPublicKey {
        self.0
    }
}
