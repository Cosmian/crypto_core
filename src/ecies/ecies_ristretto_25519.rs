use std::sync::{Arc, Mutex};

use rand_chacha::rand_core::SeedableRng;
use tiny_keccak::Hasher;

use crate::{
    asymmetric_crypto::{R25519PrivateKey, R25519PublicKey},
    kdf,
    symmetric_crypto::{
        aes_256_gcm_pure::{
            decrypt_combined, encrypt_combined, Aes256GcmCrypto, KEY_LENGTH as SYMMETRIC_KEY_LENGTH,
        },
        nonce::NonceTrait,
        Dem,
    },
    CryptoCoreError, CsRng, Ecies, FixedSizeKey, SecretKey,
};

/// A thread safe Elliptic Curve Integrated Encryption Scheme (ECIES) using
///  - the Ristretto group of Curve 25516
///  - AES 256 GCM
///  - SHAKE256 (XOF)
pub struct EciesR25519Aes256gcmSha256Xof {
    cs_rng: Arc<Mutex<CsRng>>,
}

impl EciesR25519Aes256gcmSha256Xof {
    /// Creates a new instance of `EciesR25519Aes256gcmSha256Xof`.
    #[must_use]
    pub fn new() -> Self {
        Self::new_from_rng(Arc::new(Mutex::new(CsRng::from_entropy())))
    }

    /// Creates a new instance of `EciesR25519Aes256gcmSha256Xof`
    /// from an existing cryptographic pseudo random generator
    #[must_use]
    pub fn new_from_rng(cs_rng: Arc<Mutex<CsRng>>) -> Self {
        Self { cs_rng }
    }
}

impl Default for EciesR25519Aes256gcmSha256Xof {
    fn default() -> Self {
        Self::new()
    }
}

fn get_seal_nonce<const NONCE_LENGTH: usize>(
    ephemeral_pk: &R25519PublicKey,
    recipient_pk: &R25519PublicKey,
) -> [u8; NONCE_LENGTH] {
    let mut buffer = [0u8; NONCE_LENGTH];
    let mut hasher = kdf::Shake::v256();
    hasher.update(&ephemeral_pk.to_bytes());
    hasher.update(&recipient_pk.to_bytes());
    hasher.finalize(&mut buffer);
    buffer
}

fn get_ephemeral_key<const KEY_LENGTH: usize>(shared_point: &R25519PublicKey) -> [u8; KEY_LENGTH] {
    let mut buffer = [0u8; KEY_LENGTH];
    let mut hasher = kdf::Shake::v256();
    hasher.update(&shared_point.to_bytes());
    hasher.finalize(&mut buffer);
    buffer
}

impl Ecies<R25519PrivateKey, R25519PublicKey> for EciesR25519Aes256gcmSha256Xof {
    const ENCRYPTION_OVERHEAD: usize = R25519PublicKey::LENGTH + Aes256GcmCrypto::MAC_LENGTH;

    fn encrypt(
        &self,
        recipient_pk: &R25519PublicKey,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        let ephemeral_sk = {
            let mut rng = self.cs_rng.lock().expect("failed to lock cs_rng");
            // Generate an ephemeral key pair (r, R) where R = r.G
            R25519PrivateKey::new(&mut *rng)
        };
        let ephemeral_pk = R25519PublicKey::from(&ephemeral_sk);

        // Calculate the shared secret point (Px, Py) = P = r.Y
        let shared_point = recipient_pk * &ephemeral_sk;

        // Generate the 256-bit symmetric encryption key k, derived using SHAKE256 eXtendable-Output-Function (XOF)
        // such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<SYMMETRIC_KEY_LENGTH>(&shared_point);

        // Calculate the nonce based on the 2 public keys
        let nonce = get_seal_nonce::<
            { <Aes256GcmCrypto as Dem<SYMMETRIC_KEY_LENGTH>>::Nonce::LENGTH },
        >(&ephemeral_pk, recipient_pk);

        // Encrypt and authenticate the message, returning the ciphertext and MAC
        let ciphertext_plus_tag = encrypt_combined(&key, plaintext, &nonce, authentication_data)?;

        // Assemble the final encrypted message: R || nonce || c || d
        let mut res = Vec::with_capacity(
            R25519PublicKey::LENGTH + plaintext.len() + Aes256GcmCrypto::MAC_LENGTH,
        );
        res.extend(ephemeral_pk.to_bytes());
        res.extend(&ciphertext_plus_tag);

        Ok(res)
    }

    fn decrypt(
        &self,
        recipient_sk: &R25519PrivateKey,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        // Extract the sender's ephemeral public key R from the ciphertext
        let ephemeral_pk = R25519PublicKey::try_from_slice(&ciphertext[..R25519PublicKey::LENGTH])?;

        // Calculate the shared secret point (Px, Py) = P = R.y = r.G.y = r.Y
        let shared_point = &ephemeral_pk * recipient_sk;

        // Generate the 256-bit symmetric encryption key k, derived using SHAKE256 XOF
        // such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<SYMMETRIC_KEY_LENGTH>(&shared_point);

        // Recompute the nonce
        let nonce = get_seal_nonce::<
            { <Aes256GcmCrypto as Dem<SYMMETRIC_KEY_LENGTH>>::Nonce::LENGTH },
        >(&ephemeral_pk, &R25519PublicKey::from(recipient_sk));

        // Separate the encrypted message and MAC from the ciphertext
        let ciphertext_plus_tag = &ciphertext[R25519PublicKey::LENGTH..];

        // Decrypt and verify the message using AES-256-GCM
        let decrypted_message =
            decrypt_combined(&key, ciphertext_plus_tag, &nonce, authentication_data)?;

        Ok(decrypted_message)
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoCoreError;
    use crate::{
        asymmetric_crypto::{R25519PrivateKey, R25519PublicKey},
        ecies::ecies_ristretto_25519::EciesR25519Aes256gcmSha256Xof,
        reexport::rand_core::SeedableRng,
        CsRng, Ecies, SecretKey,
    };

    #[test]
    fn test_encrypt_decrypt() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let private_key = R25519PrivateKey::new(&mut rng);
        let public_key = R25519PublicKey::from(&private_key);
        let plaintext = b"Hello, World!";

        let ecies = EciesR25519Aes256gcmSha256Xof::new();

        // Encrypt the message
        let ciphertext = ecies.encrypt(&public_key, plaintext, None)?;

        // Decrypt the message
        let plaintext_ = ecies.decrypt(&private_key, &ciphertext, None)?;

        // Check if the decrypted message is the same as the original message
        assert_eq!(plaintext, &plaintext_[..]);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_with_authenticated_data() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let private_key = R25519PrivateKey::new(&mut rng);
        let public_key = R25519PublicKey::from(&private_key);
        let plaintext = b"Hello, World!";
        let authenticated_data = b"Optional authenticated data";

        let ecies = EciesR25519Aes256gcmSha256Xof::new();

        // Encrypt the message
        let ciphertext = ecies.encrypt(&public_key, plaintext, Some(authenticated_data))?;

        // Decrypt the message
        let plaintext_ = ecies.decrypt(&private_key, &ciphertext, Some(authenticated_data))?;

        // Check if the decrypted message is the same as the original message
        assert_eq!(plaintext, &plaintext_[..]);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_with_corrupted_authentication_data() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let private_key = R25519PrivateKey::new(&mut rng);
        let public_key = R25519PublicKey::from(&private_key);
        let plaintext = b"Hello, World!";
        let authenticated_data = b"Optional authenticated data";

        let ecies = EciesR25519Aes256gcmSha256Xof::new();

        // Encrypt the message
        let ciphertext = ecies.encrypt(&public_key, plaintext, Some(authenticated_data))?;

        // Decrypt the message
        let not_decrypted = ecies.decrypt(
            &private_key,
            &ciphertext,
            Some(&b"Corrupted authenticated data"[..]),
        );

        assert!(matches!(
            not_decrypted,
            Err(CryptoCoreError::DecryptionError)
        ));

        Ok(())
    }
}
