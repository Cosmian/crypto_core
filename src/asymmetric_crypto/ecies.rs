use crate::CryptoCoreError;

pub trait Ecies<PrivateKey, PublicKey> {
    /// The size of the overhead added by the encryption process.
    const ENCRYPTION_OVERHEAD: usize;

    /// Encrypts a message using the given public key.
    fn encrypt(&self, public_key: &PublicKey, plaintext: &[u8])
        -> Result<Vec<u8>, CryptoCoreError>;

    /// Decrypts a message using the given private key.
    fn decrypt(
        &self,
        private_key: &PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoCoreError>;
}

pub trait EciesWithAuthenticationData<PrivateKey, PublicKey> {
    /// The size of the overhead added by the encryption process.
    const ENCRYPTION_OVERHEAD: usize;

    /// Encrypts a message using the given public key.
    fn encrypt_with_authentication_data(
        &self,
        public_key: &PublicKey,
        plaintext: &[u8],
        authentication_data: &[u8],
    ) -> Result<Vec<u8>, CryptoCoreError>;

    /// Decrypts a message using the given private key.
    fn decrypt_with_authentication_data(
        &self,
        private_key: &PrivateKey,
        ciphertext: &[u8],
        authentication_data: &[u8],
    ) -> Result<Vec<u8>, CryptoCoreError>;
}
