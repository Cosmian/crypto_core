use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{asymmetric_crypto::DhKeyPair, reexport::rand_core::CryptoRngCore, KeyTrait};

use super::{
    R25519PrivateKey, R25519PublicKey, R25519_PRIVATE_KEY_LENGTH, R25519_PUBLIC_KEY_LENGTH,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R25519KeyPair {
    pk: R25519PublicKey,
    sk: R25519PrivateKey,
}

impl DhKeyPair<R25519_PUBLIC_KEY_LENGTH, R25519_PRIVATE_KEY_LENGTH> for R25519KeyPair {
    type PrivateKey = R25519PrivateKey;
    type PublicKey = R25519PublicKey;

    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let sk = R25519PrivateKey::new(rng);
        let pk = R25519PublicKey::from(&sk);
        Self { pk, sk }
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.pk
    }

    fn private_key(&self) -> &Self::PrivateKey {
        &self.sk
    }
}

impl Zeroize for R25519KeyPair {
    fn zeroize(&mut self) {
        self.pk.zeroize();
        self.sk.zeroize();
    }
}

// Implements `Drop` trait to follow R23.
impl Drop for R25519KeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for R25519KeyPair {}
