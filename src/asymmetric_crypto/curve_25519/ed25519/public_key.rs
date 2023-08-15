//reexport the RustBox Ed25519 impl

use std::ops::Deref;

use ed25519_dalek::SigningKey;
pub use ed25519_dalek::{SecretKey as EdSecretKey, VerifyingKey as EdPublicKey};

use super::private_key::Ed25519PrivateKey;
use crate::{CBytes, FixedSizeCBytes};

pub const ED25519_PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ed25519PublicKey(pub(crate) EdPublicKey);

impl CBytes for Ed25519PublicKey {}

impl Ed25519PublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }
}

impl FixedSizeCBytes<{ ED25519_PUBLIC_KEY_LENGTH }> for Ed25519PublicKey {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(
        bytes: [u8; ED25519_PUBLIC_KEY_LENGTH],
    ) -> Result<Self, crate::CryptoCoreError> {
        EdPublicKey::from_bytes(&bytes)
            .map_err(|_| {
                crate::CryptoCoreError::InvalidBytesLength(
                    "public key from bytes".to_string(),
                    bytes.len(),
                    None,
                )
            })
            .map(Self)
    }
}

impl From<&Ed25519PrivateKey> for Ed25519PublicKey {
    fn from(sk: &Ed25519PrivateKey) -> Self {
        Self(EdPublicKey::from(&SigningKey::from_bytes(&sk.0)))
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
