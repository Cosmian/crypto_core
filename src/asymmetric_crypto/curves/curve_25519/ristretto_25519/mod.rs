mod curve_point;
mod private_key;

pub use curve_point::{R25519Point, R25519_POINT_LENGTH};
pub use private_key::{R25519Scalar, R25519_SCALAR_LENGTH};

#[cfg(feature = "sha3")]
use crate::{
    bytes_ser_de::Serializable,
    reexport::rand_core::CryptoRngCore,
    traits::{KeyHomomorphicNike, Sampling, NIKE},
    CryptoCoreError, SymmetricKey,
};

#[cfg(feature = "sha3")]
use tiny_keccak::{Hasher, Sha3};

pub struct R25519;

#[cfg(feature = "sha3")]
impl R25519 {
    const SESSION_KEY_LENGTH: usize = R25519_POINT_LENGTH;
}

#[cfg(feature = "sha3")]
impl NIKE<{ Self::SESSION_KEY_LENGTH }> for R25519 {
    type Error = CryptoCoreError;
    type SecretKey = R25519Scalar;
    type PublicKey = R25519Point;

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
    ) -> Result<SymmetricKey<{ Self::SESSION_KEY_LENGTH }>, Self::Error> {
        let ss = pk * sk;
        let mut key = SymmetricKey::default();
        let mut hasher = Sha3::v256();
        hasher.update(&ss.serialize()?);
        hasher.finalize(&mut *key);
        Ok(key)
    }
}

#[cfg(feature = "sha3")]
impl KeyHomomorphicNike<{ Self::SESSION_KEY_LENGTH }> for R25519 {}

#[cfg(all(test, feature = "sha3"))]
mod tests {
    use crate::{
        traits::tests::{test_homomorphic_nike, test_kem, test_nike},
        R25519,
    };

    #[test]
    fn test_r25519() {
        test_nike::<{ R25519::SESSION_KEY_LENGTH }, R25519>();
        test_kem::<{ R25519::SESSION_KEY_LENGTH }, R25519>();
        test_homomorphic_nike::<{ R25519::SESSION_KEY_LENGTH }, R25519>();
    }
}
