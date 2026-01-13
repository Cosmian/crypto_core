mod curve_point;
mod private_key;

pub use curve_point::{R25519Point, R25519_POINT_LENGTH};
pub use private_key::{R25519Scalar, R25519_SCALAR_LENGTH};

use crate::{
    reexport::rand_core::CryptoRngCore,
    traits::{KeyHomomorphicNike, Sampling, NIKE},
    CryptoCoreError,
};

pub struct R25519;

impl NIKE for R25519 {
    type Error = CryptoCoreError;
    type SecretKey = R25519Scalar;
    type PublicKey = R25519Point;
    type SessionKey = R25519Point;

    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error> {
        let dk = Self::SecretKey::random(rng);
        let ek = Self::PublicKey::from(&dk);
        Ok((dk, ek))
    }

    fn session_key(
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Result<Self::SessionKey, Self::Error> {
        Ok(pk * sk)
    }
}

impl KeyHomomorphicNike for R25519 {}

#[cfg(test)]
mod tests {
    use crate::{traits::tests::test_nike, R25519};

    #[test]
    fn test_r25519_nike() {
        test_nike::<R25519>();
    }
}
