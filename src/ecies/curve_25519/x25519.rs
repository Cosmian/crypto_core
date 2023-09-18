use crate::{
    ecies::traits::{EciesEcPrivateKey, EciesEcPublicKey, EciesEcSharedPoint},
    FixedSizeCBytes, RandomFixedSizeCBytes, X25519CurvePoint, X25519PrivateKey, X25519PublicKey,
    CURVE_25519_SECRET_LENGTH, X25519_PUBLIC_KEY_LENGTH,
};

impl EciesEcPrivateKey<CURVE_25519_SECRET_LENGTH> for X25519PrivateKey {
    fn new<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        <Self as RandomFixedSizeCBytes<{ CURVE_25519_SECRET_LENGTH }>>::new(rng)
    }
}
impl EciesEcSharedPoint for X25519PublicKey {
    fn to_vec(&self) -> Vec<u8> {
        <Self as FixedSizeCBytes<X25519_PUBLIC_KEY_LENGTH>>::to_bytes(self).to_vec()
    }
}
impl EciesEcPublicKey<CURVE_25519_SECRET_LENGTH, X25519_PUBLIC_KEY_LENGTH> for X25519CurvePoint {
    type PrivateKey = X25519PrivateKey;
    type SharedPoint = Self;

    fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_LENGTH] {
        <Self as FixedSizeCBytes<X25519_PUBLIC_KEY_LENGTH>>::to_bytes(self)
    }

    fn try_from_bytes(
        bytes: [u8; X25519_PUBLIC_KEY_LENGTH],
    ) -> Result<Self, crate::CryptoCoreError> {
        <Self as FixedSizeCBytes<X25519_PUBLIC_KEY_LENGTH>>::try_from_bytes(bytes)
    }

    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        Self::from(private_key)
    }

    fn dh(&self, private_key: &Self::PrivateKey) -> Self::SharedPoint {
        self.dh(private_key)
    }
}
