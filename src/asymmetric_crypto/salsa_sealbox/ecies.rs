use std::sync::{Arc, Mutex};

use rand_chacha::rand_core::SeedableRng;

use crate::{asymmetric_crypto::ecies::Ecies, CsRng};

use super::keypair::{X25519PrivateKey, X25519PublicKey};

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

impl Ecies<{ crypto_box::KEY_SIZE }, { crypto_box::KEY_SIZE }> for EciesSalsaSealBox {
    type PrivateKey = X25519PrivateKey;

    type PublicKey = X25519PublicKey;

    fn encrypt(
        &self,
        public_key: &Self::PublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, crate::CryptoCoreError> {
        let mut rng = self.cs_rng.lock().expect("failed to lock cs_rng");
        public_key
            .0
            .seal(&mut *rng, plaintext)
            .map_err(|_| crate::CryptoCoreError::EncryptionError)
    }

    fn decrypt(
        &self,
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, crate::CryptoCoreError> {
        private_key
            .0
            .unseal(ciphertext)
            .map_err(|_| crate::CryptoCoreError::DecryptionError)
    }

    fn ciphertext_size(&self, plaintext_size: usize) -> usize {
        plaintext_size + crypto_box::SEALBYTES
    }
}
