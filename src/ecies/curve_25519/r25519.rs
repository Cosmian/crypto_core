use crate::{
    bytes_ser_de::Serializable,
    ecies::traits::{EciesEcPrivateKey, EciesEcPublicKey, EciesEcSharedPoint},
    traits::Sampling,
    R25519Point, R25519Scalar, R25519_POINT_LENGTH, R25519_SCALAR_LENGTH,
};

impl EciesEcPrivateKey<32> for R25519Scalar {
    fn new<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        <Self as Sampling>::random(rng)
    }
}

impl EciesEcSharedPoint for R25519Point {
    fn to_vec(&self) -> Vec<u8> {
        <[u8; R25519_POINT_LENGTH]>::from(self).to_vec()
    }
}

impl EciesEcPublicKey<R25519_SCALAR_LENGTH, R25519_POINT_LENGTH> for R25519Point {
    type PrivateKey = R25519Scalar;
    type SharedPoint = Self;

    fn to_bytes(&self) -> [u8; R25519_POINT_LENGTH] {
        <[u8; R25519_POINT_LENGTH]>::from(self)
    }

    fn try_from_bytes(bytes: [u8; R25519_POINT_LENGTH]) -> Result<Self, crate::CryptoCoreError> {
        Self::deserialize(&bytes)
    }

    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        Self::from(private_key)
    }

    fn dh(&self, private_key: &Self::PrivateKey) -> Self::SharedPoint {
        self * private_key
    }
}
