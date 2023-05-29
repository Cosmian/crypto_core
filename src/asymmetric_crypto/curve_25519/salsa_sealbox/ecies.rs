use std::sync::{Arc, Mutex};

use crypto_box::{PublicKey, SecretKey};
use rand_chacha::rand_core::SeedableRng;

use crate::{
    asymmetric_crypto::{ecies::Ecies, X25519PrivateKey},
    CsRng,
};

use super::X25519PublicKey;

/// The `EciesSalsaSealBox` struct provides Elliptic Curve Integrated Encryption Scheme (ECIES) functionality
/// utilizing Salsa20 as its encryption mechanism.
///
/// This implementation is compatible with `libsodium` sealed box: `<https://doc.libsodium.org/public-key_cryptography/sealed_boxe>`
///
/// This struct is used for public-key encryption and decryption where the `X25519PrivateKey` and `X25519PublicKey` types are used.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use rand_chacha::rand_core::SeedableRng;
/// use cosmian_crypto_core::{
///     asymmetric_crypto:: {
///         Ecies,
///         EciesSalsaSealBox, X25519PrivateKey, X25519PublicKey,
///     },
///    CsRng, KeyTrait,
///};
///
/// // Instantiate a cryptographic random number generator
/// let arc_rng = Arc::new(Mutex::new(CsRng::from_entropy()));
///
/// // Create a new instance of EciesSalsaSealBox
/// let ecies = EciesSalsaSealBox::new_from_rng(arc_rng.clone());
///
/// // Generate a secret key
/// let private_key = {
///     let mut rng = arc_rng.lock().unwrap();
///     X25519PrivateKey::new(&mut *rng)
/// };
/// let public_key = private_key.public_key();
///
/// // The plaintext message to be encrypted
/// let plaintext = b"Hello World!";
///
/// // Encrypt the plaintext message with the public key
/// let ciphertext = ecies.encrypt(&public_key, plaintext).unwrap();
///
/// // Verify that the size of the ciphertext is as expected
/// assert_eq!(ciphertext.len(), plaintext.len() + EciesSalsaSealBox::ENCRYPTION_OVERHEAD);
///
/// // Decrypt the ciphertext back into plaintext with the private key
/// let plaintext_ = ecies.decrypt(&private_key, &ciphertext).unwrap();
///
/// // Check that the decrypted text matches the original plaintext
/// assert_eq!(plaintext, &plaintext_[..]);
/// ```
///
/// The `new_from_rng` function allows the use of a custom random number generator.
pub struct EciesSalsaSealBox {
    cs_rng: Arc<Mutex<CsRng>>,
}

impl EciesSalsaSealBox {
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

impl Default for EciesSalsaSealBox {
    fn default() -> Self {
        Self::new()
    }
}

impl Ecies<X25519PrivateKey, X25519PublicKey> for EciesSalsaSealBox {
    const ENCRYPTION_OVERHEAD: usize = crypto_box::SEALBYTES;

    fn encrypt(
        &self,
        public_key: &X25519PublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, crate::CryptoCoreError> {
        let mut rng = self.cs_rng.lock().expect("failed to lock cs_rng");
        let public_key: PublicKey = public_key.0.into();
        public_key
            .seal(&mut *rng, plaintext)
            .map_err(|_| crate::CryptoCoreError::EncryptionError)
    }

    fn decrypt(
        &self,
        private_key: &X25519PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, crate::CryptoCoreError> {
        let secret_key: SecretKey = private_key.0.into();
        secret_key
            .unseal(ciphertext)
            .map_err(|_| crate::CryptoCoreError::DecryptionError)
    }
}
