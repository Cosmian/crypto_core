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
