use std::ops::{Add, Div, Mul, Sub};

use curve25519_dalek::Scalar;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "ser")]
use crate::bytes_ser_de::{Deserializer, Serializable, Serializer};
use crate::{CBytes, CryptoCoreError, FixedSizeCBytes, RandomFixedSizeCBytes, SecretCBytes};

const PRIVATE_KEY_LENGTH: usize = 32;

#[derive(Hash, Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct R25519PrivateKey(pub(crate) Scalar);

impl CBytes for R25519PrivateKey {}

impl FixedSizeCBytes<{ PRIVATE_KEY_LENGTH }> for R25519PrivateKey {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(bytes: [u8; Self::LENGTH]) -> Result<Self, CryptoCoreError> {
        <Option<_>>::from(Scalar::from_canonical_bytes(bytes))
            .map(Self)
            .ok_or_else(|| {
                CryptoCoreError::ConversionError(
                    "given bytes do not represent a canonical scalar".to_string(),
                )
            })
    }
}

impl RandomFixedSizeCBytes<{ PRIVATE_KEY_LENGTH }> for R25519PrivateKey {
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0; 2 * Self::LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(Scalar::from_bytes_mod_order_wide(&bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl SecretCBytes<{ PRIVATE_KEY_LENGTH }> for R25519PrivateKey {}

/// Key Serialization framework
#[cfg(feature = "ser")]
impl Serializable for R25519PrivateKey {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        Self::LENGTH
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_array(self.as_bytes())
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<{ Self::LENGTH }>()?;
        Self::try_from_bytes(bytes)
    }
}

// Curve arithmetic

impl<'a> Add<&'a R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn add(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn sub(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn mul(self, rhs: &R25519PrivateKey) -> Self::Output {
        R25519PrivateKey(self.0 * rhs.0)
    }
}

impl<'a> Div<&'a R25519PrivateKey> for &R25519PrivateKey {
    type Output = R25519PrivateKey;

    fn div(self, rhs: &R25519PrivateKey) -> Self::Output {
        #[allow(clippy::suspicious_arithmetic_impl)]
        R25519PrivateKey(self.0 * rhs.0.invert())
    }
}
