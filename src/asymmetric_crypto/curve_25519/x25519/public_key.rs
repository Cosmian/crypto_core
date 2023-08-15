use curve25519_dalek::{scalar::clamp_integer, MontgomeryPoint, Scalar};

use super::X25519PrivateKey;
use crate::{CBytes, FixedSizeCBytes};

/// Length of a X25519 public key in bytes.
pub const X25519_PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct X25519PublicKey(pub(crate) MontgomeryPoint);

impl X25519PublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }
}

impl CBytes for X25519PublicKey {}

impl FixedSizeCBytes<{ X25519_PUBLIC_KEY_LENGTH }> for X25519PublicKey {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(
        bytes: [u8; X25519_PUBLIC_KEY_LENGTH],
    ) -> Result<Self, crate::CryptoCoreError> {
        Ok(Self(MontgomeryPoint(bytes)))
    }
}

impl From<&X25519PrivateKey> for X25519PublicKey {
    fn from(sk: &X25519PrivateKey) -> Self {
        Self(MontgomeryPoint::mul_base(&Scalar::from_bytes_mod_order(
            clamp_integer(sk.0),
        )))
    }
}

impl X25519PublicKey {
    #[must_use]
    pub fn dh(&self, rhs: &X25519PrivateKey) -> Self {
        Self(self.0 * Scalar::from_bytes_mod_order(clamp_integer(rhs.0)))
    }
}
