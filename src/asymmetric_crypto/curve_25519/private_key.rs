use rand_chacha::rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "ser")]
use crate::bytes_ser_de::{Deserializer, Serializable, Serializer};
use crate::{CBytes, CryptoCoreError, FixedSizeCBytes, RandomFixedSizeCBytes, SecretCBytes};

/// Length of a Curve25519 private key in bytes.
pub const CURVE_25519_PRIVATE_KEY_LENGTH: usize = 32;

/// Asymmetric private key based on Curve25519.
///
/// This type wraps a scalar which is clamped to the curve.
/// `Curve25519PrivateKey` should not be used directly
/// but rather re-used as a base type for other final types on the curve
/// such as `X25519PrivateKey`.
#[derive(Hash, Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Curve25519Secret(pub(crate) [u8; CURVE_25519_PRIVATE_KEY_LENGTH]);

impl CBytes for Curve25519Secret {}

impl FixedSizeCBytes<{ CURVE_25519_PRIVATE_KEY_LENGTH }> for Curve25519Secret {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0
    }

    fn try_from_bytes(bytes: [u8; Self::LENGTH]) -> Result<Self, CryptoCoreError> {
        Ok(Self(bytes))
    }
}

impl RandomFixedSizeCBytes<{ CURVE_25519_PRIVATE_KEY_LENGTH }> for Curve25519Secret {
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0; Self::LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SecretCBytes<{ CURVE_25519_PRIVATE_KEY_LENGTH }> for Curve25519Secret {}

/// Key Serialization framework
#[cfg(feature = "ser")]
impl Serializable for Curve25519Secret {
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
