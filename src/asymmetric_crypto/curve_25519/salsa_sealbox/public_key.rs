use crate::{FixedSizeKey, Key};
use curve25519_dalek::MontgomeryPoint;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::X25519PrivateKey;

// pub const X25519_PUBLIC_KEY_LENGTH: usize = crypto_box::KEY_SIZE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(pub(crate) MontgomeryPoint);

impl Key for X25519PublicKey {}

impl FixedSizeKey<{ crypto_box::KEY_SIZE }> for X25519PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().into()
    }

    fn try_from_slice(slice: &[u8]) -> Result<Self, crate::CryptoCoreError> {
        slice
            .try_into()
            .map(MontgomeryPoint)
            .map(Self)
            .map_err(|_| crate::CryptoCoreError::InvalidKeyLength)
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
