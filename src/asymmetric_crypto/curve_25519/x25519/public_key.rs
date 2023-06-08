use crate::{CBytes, FixedSizeCBytes};
use curve25519_dalek::MontgomeryPoint;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::X25519PrivateKey;

// pub const X25519_PUBLIC_KEY_LENGTH: usize = crypto_box::KEY_SIZE;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct X25519PublicKey(pub(crate) MontgomeryPoint);

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
        X25519PublicKey(MontgomeryPoint::mul_base(&sk.0))
    }
}

impl Zeroize for X25519PublicKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for X25519PublicKey {}

// Implements `Drop` trait to follow R23.
impl Drop for X25519PublicKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
