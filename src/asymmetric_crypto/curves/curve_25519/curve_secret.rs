use rand_chacha::rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    CBytes, CryptoCoreError, FixedSizeCBytes, RandomFixedSizeCBytes, SecretCBytes,
};

/// Length of a Curve25519 secret in bytes.
pub const CURVE_25519_SECRET_LENGTH: usize = 32;

/// Secret from which the private keys are derived
#[derive(Hash, Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Curve25519Secret(pub(crate) [u8; CURVE_25519_SECRET_LENGTH]);

impl CBytes for Curve25519Secret {}

impl FixedSizeCBytes<{ CURVE_25519_SECRET_LENGTH }> for Curve25519Secret {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0
    }

    fn try_from_bytes(bytes: [u8; Self::LENGTH]) -> Result<Self, CryptoCoreError> {
        Ok(Self(bytes))
    }
}

impl RandomFixedSizeCBytes<{ CURVE_25519_SECRET_LENGTH }> for Curve25519Secret {
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = [0; Self::LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SecretCBytes<{ CURVE_25519_SECRET_LENGTH }> for Curve25519Secret {}

/// Key Serialization framework
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

/// Facades
///
/// Facades are used to hide the underlying types and provide a more
/// user friendly interface to the user.
impl Curve25519Secret {
    /// Generate a random private key
    ///
    /// This is a facade to `RandomFixedSizeCBytes::new`
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        <Self as RandomFixedSizeCBytes<CURVE_25519_SECRET_LENGTH>>::new(rng)
    }

    /// Get the underlying bytes slice of the private key
    ///
    /// This is a facade to `RandomFixedSizeCBytes::as_bytes`
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        <Self as RandomFixedSizeCBytes<CURVE_25519_SECRET_LENGTH>>::as_bytes(self)
    }

    /// Serialize the `PrivateKey` as a non zero scalar
    ///
    /// This is a facade to `<Self as FixedSizeCBytes>::to_bytes`
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CURVE_25519_SECRET_LENGTH] {
        <Self as FixedSizeCBytes<CURVE_25519_SECRET_LENGTH>>::to_bytes(self)
    }

    /// Deserialize the `PrivateKey` from a non zero scalar
    ///
    /// This is a facade to `<Self as
    /// FixedSizeCBytes<CURVE_25519_SECRET_LENGTH>>::try_from_bytes`
    pub fn try_from_bytes(bytes: [u8; CURVE_25519_SECRET_LENGTH]) -> Result<Self, CryptoCoreError> {
        <Self as FixedSizeCBytes<CURVE_25519_SECRET_LENGTH>>::try_from_bytes(bytes)
    }
}
