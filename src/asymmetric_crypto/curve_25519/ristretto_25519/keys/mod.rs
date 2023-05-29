//! Define the `R25519PublicKey` and `R25519PrivateKey` objects, asymmetric
//! keys based on the Ristretto group for Curve25519.
//!
//! Curve25519 is an elliptic curve defined by the equation `y^2 = x^3 +
//! 486662x^2 + x`. Its security level is 128-bits. It is the fastest curve
//! available at the time of this implementation.
//!
//! See `<https://ristretto.group/ristretto.html>` for more information on Ristretto.

mod public_key;
pub use public_key::R25519PublicKey;

mod dh_keypair;
pub use dh_keypair::R25519KeyPair;

use crate::asymmetric_crypto::curve_25519::private_key::Curve25519PrivateKey;

pub type R25519PrivateKey = Curve25519PrivateKey;

#[cfg(test)]
mod test {
    use super::{R25519KeyPair, R25519PrivateKey, R25519PublicKey};
    use crate::{
        asymmetric_crypto::DhKeyPair, reexport::rand_core::SeedableRng, CsRng, FixedSizeKey,
        SecretKey,
    };

    #[test]
    fn test_private_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519PrivateKey::new(&mut rng);
        let bytes = sk.to_bytes();
        let recovered = R25519PrivateKey::try_from_slice(&bytes).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_public_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519PrivateKey::new(&mut rng);
        let pk = R25519PublicKey::from(&sk);
        let bytes = pk.to_bytes();
        let recovered = R25519PublicKey::try_from_slice(&bytes).unwrap();
        assert_eq!(pk, recovered);
    }

    #[test]
    fn test_dh_key_pair() {
        let mut rng = CsRng::from_entropy();
        let kp1 = R25519KeyPair::new(&mut rng);
        let kp2 = R25519KeyPair::new(&mut rng);
        // check the keys are randomly generated
        assert_ne!(kp1, kp2);
        // check DH Key exchange is possible
        assert_eq!(
            kp1.public_key() * kp2.private_key(),
            kp2.public_key() * kp1.private_key()
        );
    }
}
