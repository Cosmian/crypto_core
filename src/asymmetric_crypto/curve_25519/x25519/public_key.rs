use curve25519_dalek::{scalar::clamp_integer, MontgomeryPoint, Scalar};

use super::X25519PrivateKey;
use crate::{CBytes, Ed25519PublicKey, FixedSizeCBytes};

/// Length of a X25519 public key in bytes.
pub const X25519_PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct X25519PublicKey(pub(crate) MontgomeryPoint);

impl X25519PublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Convert an Ed25519 public key to a X25519 public key.
    ///
    /// The corresponding private key of the Ed25519 keypair should be converted to a X25519 private key.
    /// See [`X25519PrivateKey::from_ed25519_private_key`] for more details.
    pub fn from_ed25519_public_key(ed25519_public_key: &Ed25519PublicKey) -> Self {
        Self(ed25519_public_key.0.to_montgomery())
    }
}

impl CBytes for X25519PublicKey {}

impl FixedSizeCBytes<{ X25519_PUBLIC_KEY_LENGTH }> for X25519PublicKey {
    fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    fn try_from_bytes(
        bytes: [u8; X25519_PUBLIC_KEY_LENGTH],
    ) -> Result<Self, crate::CryptoCoreError> {
        Ok(Self(MontgomeryPoint(bytes)))
    }
}

impl From<&X25519PrivateKey> for X25519PublicKey {
    fn from(sk: &X25519PrivateKey) -> Self {
        Self(MontgomeryPoint::mul_base(&Scalar::from_bytes_mod_order(
            clamp_integer(sk.0),
        )))
    }
}

impl X25519PublicKey {
    #[must_use]
    pub fn dh(&self, rhs: &X25519PrivateKey) -> Self {
        Self(self.0 * Scalar::from_bytes_mod_order(clamp_integer(rhs.0)))
    }
}

#[cfg(test)]
mod test {

    use crate::{
        CsRng, Ed25519PrivateKey, Ed25519PublicKey, RandomFixedSizeCBytes, X25519PrivateKey,
        X25519PublicKey,
    };
    use rand_core::SeedableRng;

    #[test]
    fn test_ed25519_to_x25519() {
        let mut rng = CsRng::from_entropy();
        let ed25519_sk = Ed25519PrivateKey::new(&mut rng);
        let ed25519_pk = Ed25519PublicKey::from(&ed25519_sk);

        // convert the ED25519 private key to an X25519 PrivateKey
        let x25519_sk = X25519PrivateKey::from_ed25519_private_key(&ed25519_sk);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        assert_eq!(
            x25519_pk,
            X25519PublicKey::from_ed25519_public_key(&ed25519_pk)
        );
    }
}
