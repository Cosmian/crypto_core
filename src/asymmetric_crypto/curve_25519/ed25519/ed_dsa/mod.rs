//! Edwards Digital Signature Algorithm (EdDSA) over Curve25519 as specified in RFC 8032.
//! https://tools.ietf.org/html/rfc8032

mod key_pair;
mod signer;
mod verifier;

pub use key_pair::Ed25519Keypair;
pub use signer::Cached25519Signer;

#[cfg(test)]
mod tests {

    use crate::asymmetric_crypto::curve_25519::ed25519::Ed25519PrivateKey;
    use crate::asymmetric_crypto::curve_25519::ed25519::Ed25519PublicKey;
    use crate::asymmetric_crypto::Ed25519Keypair;
    use crate::reexport::rand_core::SeedableRng;
    use crate::FixedSizeKey;
    use crate::SecretKey;
    use signature::Signer;
    use signature::Verifier;

    use crate::CsRng;

    use super::Cached25519Signer;

    #[test]
    fn ed25519_test() {
        let mut rng = CsRng::from_entropy();
        let message = b"Hello, world!";

        // sign the message
        let private_key = Ed25519PrivateKey::new(&mut rng);
        let signature = private_key.try_sign(message).unwrap();

        // verify the signature
        let public_key = Ed25519PublicKey::from(&private_key);
        public_key.verify(message, &signature).unwrap();
    }

    #[test]
    fn ed25519_cached_test() {
        let mut rng = CsRng::from_entropy();

        // instantiate the cached signer
        let private_key = Ed25519PrivateKey::new(&mut rng);
        let cached_signer = Cached25519Signer::try_from(&private_key).unwrap();

        // verify the signatures
        let public_key = Ed25519PublicKey::from(&private_key);

        let message = b"Hello, world!";
        let signature = cached_signer.try_sign(message).unwrap();
        public_key.verify(message, &signature).unwrap();

        let message = b"I'm sorry, Dave. I'm afraid I can't do that.";
        let signature = cached_signer.try_sign(message).unwrap();
        public_key.verify(message, &signature).unwrap();
    }

    #[test]
    fn ed25519_keypair_test() {
        let mut rng = CsRng::from_entropy();
        let message = b"Hello, world!";

        // generate a keypair
        let keypair = Ed25519Keypair::new(&mut rng);

        // serialize the keypair
        let serialized_keypair = keypair.to_bytes();

        // deserialize the keypair
        let keypair = Ed25519Keypair::try_from_bytes(serialized_keypair).unwrap();

        //assert equality
        assert_eq!(keypair.to_bytes(), serialized_keypair);

        // sign the message using the keypair
        let signature = keypair.try_sign(message).unwrap();

        // verify the signature
        keypair.verify(message, &signature).unwrap();
    }
}
