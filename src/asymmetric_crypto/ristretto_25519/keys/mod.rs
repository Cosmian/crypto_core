//! Define the `R25519PublicKey` and `R25519PrivateKey` objects, asymmetric
//! keys based on the Ristretto group for Curve25519.
//!
//! Curve25519 is an elliptic curve defined by the equation `y^2 = x^3 +
//! 486662x^2 + x`. Its security level is 128-bits. It is the fastest curve
//! available at the time of this implementation.
//!
//! See `<https://ristretto.group/ristretto.html>` for more information on Ristretto.

mod private_key;
pub use private_key::{R25519PrivateKey, R25519_PRIVATE_KEY_LENGTH};

mod public_key;
pub use public_key::{R25519PublicKey, R25519_PUBLIC_KEY_LENGTH};

mod dh_keypair;
pub use dh_keypair::R25519KeyPair;

#[cfg(test)]
mod test {
    use super::{
        R25519KeyPair, R25519PrivateKey, R25519PublicKey, R25519_PRIVATE_KEY_LENGTH,
        R25519_PUBLIC_KEY_LENGTH,
    };
    use crate::{asymmetric_crypto::DhKeyPair, reexport::rand_core::SeedableRng, CsRng, KeyTrait};

    #[test]
    fn test_private_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let sk = R25519PrivateKey::new(&mut rng);
        let bytes: [u8; R25519_PRIVATE_KEY_LENGTH] = sk.to_bytes();
        let recovered = R25519PrivateKey::try_from(bytes).unwrap();
        assert_eq!(sk, recovered);
    }

    #[test]
    fn test_public_key_serialization() {
        let mut rng = CsRng::from_entropy();
        let pk = R25519PublicKey::new(&mut rng);
        let bytes: [u8; R25519_PUBLIC_KEY_LENGTH] = pk.to_bytes();
        let recovered = R25519PublicKey::try_from(bytes).unwrap();
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
