use crate::{CBytes, FixedSizeCBytes};
use curve25519_dalek::MontgomeryPoint;
use std::ops::Mul;

use super::X25519PrivateKey;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct X25519PublicKey(pub(crate) MontgomeryPoint);

impl X25519PublicKey {
    pub fn as_bytes(&self) -> &[u8; crypto_box::KEY_SIZE] {
        self.0.as_bytes()
    }
}

impl CBytes for X25519PublicKey {}

impl FixedSizeCBytes<{ crypto_box::KEY_SIZE }> for X25519PublicKey {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(bytes: [u8; crypto_box::KEY_SIZE]) -> Result<Self, crate::CryptoCoreError> {
        Ok(Self(MontgomeryPoint(bytes)))
    }
}

impl From<&X25519PrivateKey> for X25519PublicKey {
    fn from(sk: &X25519PrivateKey) -> Self {
        Self(MontgomeryPoint::mul_base(&sk.0))
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for &X25519PublicKey {
    type Output = X25519PublicKey;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PublicKey(self.0 * rhs.0)
    }
}
