use crate::{CryptoBaseError, KeyTrait};
use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    ops::{Add, Mul, Sub},
};
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "Vec<u8>")]
pub struct X25519PrivateKey(Scalar);

impl X25519PrivateKey {
    #[must_use]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }

    #[must_use]
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }
}

impl KeyTrait for X25519PrivateKey {
    const LENGTH: usize = 32;

    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoBaseError> {
        Self::try_from(bytes)
    }
}

impl TryFrom<Vec<u8>> for X25519PrivateKey {
    type Error = CryptoBaseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519PrivateKey {
    type Error = CryptoBaseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let len = bytes.len();
        let bytes: [u8; <Self>::LENGTH] = bytes.try_into().map_err(|_| Self::Error::SizeError {
            given: len,
            expected: <Self>::LENGTH,
        })?;
        let scalar = Scalar::from_canonical_bytes(bytes).ok_or_else(|| {
            Self::Error::ConversionError(
                "Given bytes do not represent a cannonical Scalar!".to_string(),
            )
        })?;
        Ok(Self(scalar))
    }
}

impl From<X25519PrivateKey> for Vec<u8> {
    fn from(key: X25519PrivateKey) -> Self {
        key.to_bytes()
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PrivateKey {
    type Error = CryptoBaseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Self::try_from(bytes)
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 * rhs.0)
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 * rhs.0)
    }
}

impl Add for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PrivateKey> for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<X25519PrivateKey> for &'a X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl Sub for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Sub<&'a X25519PrivateKey> for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl Sub<X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Sub<&'a X25519PrivateKey> for &X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl Zeroize for X25519PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "Vec<u8>")]
pub struct X25519PublicKey(RistrettoPoint);

impl X25519PublicKey {
    //compressed
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from(&X25519PrivateKey::new(rng))
    }
}

impl KeyTrait for X25519PublicKey {
    const LENGTH: usize = 32;

    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.compress().as_bytes().to_vec()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoBaseError> {
        Self::try_from(bytes)
    }
}

impl From<&X25519PrivateKey> for X25519PublicKey {
    fn from(private_key: &X25519PrivateKey) -> Self {
        Self(&private_key.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl TryFrom<Vec<u8>> for X25519PublicKey {
    type Error = CryptoBaseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519PublicKey {
    type Error = CryptoBaseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let len = value.len();
        if len != <Self>::LENGTH {
            return Err(Self::Error::SizeError {
                given: len,
                expected: <Self>::LENGTH,
            });
        };
        let compressed = CompressedRistretto::from_slice(value);
        let point = compressed.decompress().ok_or_else(|| {
            Self::Error::ConversionError(
                "Cannot decompress given bytes into a valid curve point!".to_string(),
            )
        })?;
        Ok(Self(point))
    }
}

impl From<X25519PublicKey> for Vec<u8> {
    fn from(key: X25519PublicKey) -> Self {
        key.to_bytes()
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PublicKey {
    type Error = CryptoBaseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Self::try_from(bytes.as_slice())
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.compress().to_bytes()))
    }
}

impl Add for X25519PublicKey {
    type Output = Self;

    fn add(self, rhs: X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PublicKey> for X25519PublicKey {
    type Output = X25519PublicKey;

    fn add(self, rhs: &X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PublicKey> for &X25519PublicKey {
    type Output = X25519PublicKey;

    fn add(self, rhs: &X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for &X25519PublicKey {
    type Output = X25519PublicKey;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        X25519PublicKey(self.0 * rhs.0)
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for X25519PublicKey {
    type Output = Self;

    fn mul(self, rhs: &X25519PrivateKey) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

#[cfg(test)]
mod test {
    use crate::{asymmetric::X25519PrivateKey, entropy::CsRng};

    use super::X25519PublicKey;

    #[test]
    fn test_parse_private_key() {
        let mut rng = CsRng::new();
        let sk = X25519PrivateKey::new(&mut rng);
        let hex = format!("{}", sk);
        let recovered =
            super::X25519PrivateKey::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_parse_public_key() {
        let mut rng = CsRng::new();
        let pk = X25519PublicKey::new(&mut rng);
        let hex = format!("{}", pk);
        let recovered =
            super::X25519PublicKey::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(pk, recovered);
    }
}
