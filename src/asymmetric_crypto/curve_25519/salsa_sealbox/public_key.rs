use crate::{FixedSizeKey, Key};
use curve25519_dalek::MontgomeryPoint;
use zeroize::{Zeroize, ZeroizeOnDrop};

// pub const X25519_PUBLIC_KEY_LENGTH: usize = crypto_box::KEY_SIZE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(pub(crate) MontgomeryPoint);

impl Key for X25519PublicKey {}

impl FixedSizeKey for X25519PublicKey {
    const LENGTH: usize = crypto_box::KEY_SIZE;

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

// impl KeyTrait<{ X25519_PUBLIC_KEY_LENGTH }> for X25519PublicKey {
//     fn new<R: CryptoRngCore>(_rng: &mut R) -> Self {
//         panic!("it does not make sense to construct a public key from arbitrary bytes")
//     }

//     fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_LENGTH] {
//         self.0.to_bytes()
//     }

//     fn try_from_bytes(slice: &[u8]) -> Result<Self, crate::CryptoCoreError> {
//         slice
//             .try_into()
//             .map(MontgomeryPoint)
//             .map(Self)
//             .map_err(|_| crate::CryptoCoreError::InvalidKeyLength)
//     }

//     fn as_slice(&self) -> &[u8] {
//         self.0.as_bytes()
//     }

//     fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
//         X25519PublicKey(MontgomeryPoint(bytes))
//     }
// }

impl Zeroize for X25519PublicKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for X25519PublicKey {}
