use crate::{CryptoCoreError, KeyTrait};

pub trait Ecies<const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize> {
    type PrivateKey: KeyTrait<PRIVATE_KEY_LENGTH>;
    type PublicKey: KeyTrait<PUBLIC_KEY_LENGTH>;

    /// Encrypts a message using the given public key.
    fn encrypt(
        &self,
        public_key: &Self::PublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoCoreError>;

    /// Decrypts a message using the given private key.
    fn decrypt(
        &self,
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoCoreError>;
}
