use crate::{reexport::rand_core::CryptoRngCore, CryptoCoreError};

mod ecies_ristretto_25519;
mod ecies_salsa_sealed_box;

pub use ecies_ristretto_25519::EciesR25519Aes128;
pub use ecies_salsa_sealed_box::EciesSalsaSealBox;

pub trait Ecies<PrivateKey, PublicKey> {
    /// The size of the overhead added by the encryption process.
    const ENCRYPTION_OVERHEAD: usize;

    /// Encrypts a message using the given public key
    /// and optional authentication data.
    ///
    /// Not: some algorithms, typically the sealed box variants of ECIES,
    /// based on Salsa, do not support authentication data.
    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        public_key: &PublicKey,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError>;

    /// Decrypts a message using the given private key
    /// and optional authentication data.
    ///
    /// Note: some algorithms, typically the sealed box variants of ECIES,
    /// based on Salsa, do not support authentication data.
    fn decrypt(
        private_key: &PrivateKey,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError>;
}
