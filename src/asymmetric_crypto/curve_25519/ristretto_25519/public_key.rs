use core::ops::{Add, Mul, Sub};

use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{bytes_ser_de::Serializable, CBytes, CryptoCoreError, FixedSizeCBytes};

use super::R25519PrivateKey;

/// Asymmetric public key based on the Ristretto Curve25519.
///
/// Internally, a Ristretto point is used. It is 256-bits long, but its
/// compressed form is used for serialization, which makes it 128-bits long.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct R25519PublicKey(pub(crate) RistrettoPoint);

impl CBytes for R25519PublicKey {}

impl FixedSizeCBytes<32> for R25519PublicKey {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.compress().to_bytes()
    }

    fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, crate::CryptoCoreError> {
        Ok(Self(CompressedRistretto(bytes).decompress().ok_or_else(
            || {
                CryptoCoreError::ConversionError(
                    "Cannot decompress given bytes into a valid curve point!".to_string(),
                )
            },
        )?))
    }
}

impl From<&R25519PrivateKey> for R25519PublicKey {
    fn from(private_key: &R25519PrivateKey) -> Self {
        R25519PublicKey(RistrettoPoint::mul_base(&private_key.0))
    }
}

impl Serializable for R25519PublicKey {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        ser.write_array(&self.0.compress().to_bytes())
    }

    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Self::try_from_bytes(de.read_array::<{ Self::LENGTH }>()?)
    }
}

impl From<R25519PrivateKey> for R25519PublicKey {
    fn from(private_key: R25519PrivateKey) -> Self {
        Self(&private_key.0 * constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl<'a> Sub<&'a R25519PublicKey> for &R25519PublicKey {
    type Output = R25519PublicKey;

    fn sub(self, rhs: &R25519PublicKey) -> Self::Output {
        R25519PublicKey(self.0 - rhs.0)
    }
}

impl<'a> Add<&'a R25519PublicKey> for &R25519PublicKey {
    type Output = R25519PublicKey;

    fn add(self, rhs: &R25519PublicKey) -> Self::Output {
        R25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a> Mul<&'a R25519PrivateKey> for &R25519PublicKey {
    type Output = R25519PublicKey;

    fn mul(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PublicKey(self.0 * rhs.0)
    }
}

impl Zeroize for R25519PublicKey {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

// Implements `Drop` trait to follow R23.
impl Drop for R25519PublicKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for R25519PublicKey {}

#[cfg(test)]
mod test {
    use super::{R25519PrivateKey, R25519PublicKey};
    use crate::{reexport::rand_core::SeedableRng, CsRng, FixedSizeCBytes, RandomFixedSizeCBytes};

    #[test]
    fn test_private_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519PrivateKey::new(&mut rng);
        let bytes = sk.to_bytes();
        let recovered = R25519PrivateKey::try_from_bytes(bytes).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_public_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519PrivateKey::new(&mut rng);
        let pk = R25519PublicKey::from(&sk);
        let bytes = pk.to_bytes();
        let recovered = R25519PublicKey::try_from_bytes(bytes).unwrap();
        assert_eq!(pk, recovered);
    }
}
