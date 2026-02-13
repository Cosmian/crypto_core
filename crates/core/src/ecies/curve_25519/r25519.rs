use crate::{
    ecies::traits::{EciesEcPrivateKey, EciesEcPublicKey, EciesEcSharedPoint},
    FixedSizeCBytes, R25519CurvePoint, R25519PrivateKey, R25519PublicKey, RandomFixedSizeCBytes,
    R25519_PRIVATE_KEY_LENGTH, R25519_PUBLIC_KEY_LENGTH,
};

impl EciesEcPrivateKey<R25519_PRIVATE_KEY_LENGTH> for R25519PrivateKey {
    fn new<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        <Self as RandomFixedSizeCBytes<{ R25519_PRIVATE_KEY_LENGTH }>>::new(rng)
    }
}

impl EciesEcSharedPoint for R25519PublicKey {
    fn to_vec(&self) -> Vec<u8> {
        <Self as FixedSizeCBytes<R25519_PUBLIC_KEY_LENGTH>>::to_bytes(self).to_vec()
    }
}

impl EciesEcPublicKey<R25519_PRIVATE_KEY_LENGTH, R25519_PUBLIC_KEY_LENGTH> for R25519CurvePoint {
    type PrivateKey = R25519PrivateKey;
    type SharedPoint = Self;

    fn to_bytes(&self) -> [u8; R25519_PUBLIC_KEY_LENGTH] {
        <Self as FixedSizeCBytes<R25519_PUBLIC_KEY_LENGTH>>::to_bytes(self)
    }

    fn try_from_bytes(
        bytes: [u8; R25519_PUBLIC_KEY_LENGTH],
    ) -> Result<Self, crate::CryptoCoreError> {
        <Self as FixedSizeCBytes<R25519_PUBLIC_KEY_LENGTH>>::try_from_bytes(bytes)
    }

    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        Self::from(private_key)
    }

    fn dh(&self, private_key: &Self::PrivateKey) -> Self::SharedPoint {
        self * private_key
    }
}
