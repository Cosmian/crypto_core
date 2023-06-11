use std::ops::Sub;

use aead::{
    consts::{U4, U5},
    generic_array::ArrayLength,
    stream::{DecryptorBE32, DecryptorLE31, EncryptorBE32, EncryptorLE31},
    AeadCore, AeadInPlace, KeyInit,
};

use crate::{reexport::rand_core::CryptoRngCore, CryptoCoreError};

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

pub trait EciesStreamEncryptor<PrivateKey, PublicKey, RustCryptoBackend>
where
    RustCryptoBackend: AeadInPlace + KeyInit,
    <RustCryptoBackend as AeadCore>::NonceSize: Sub<U5>,
    <RustCryptoBackend as AeadCore>::NonceSize: Sub<U4>,
    <<RustCryptoBackend as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
    <<RustCryptoBackend as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>,
{
    fn new(recipient_public_key: &PublicKey) -> Self;

    fn get_ephemeral_public_key(&self) -> PublicKey;

    fn get_dem_encryptor_be32(&self) -> EncryptorBE32<RustCryptoBackend>;
    fn get_dem_encryptor_le31(&self) -> EncryptorLE31<RustCryptoBackend>;
}

pub trait EciesStreamDecryptor<PrivateKey, PublicKey, RustCryptoBackend>
where
    RustCryptoBackend: AeadInPlace + KeyInit,
    <RustCryptoBackend as AeadCore>::NonceSize: Sub<U5>,
    <RustCryptoBackend as AeadCore>::NonceSize: Sub<U4>,
    <<RustCryptoBackend as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
    <<RustCryptoBackend as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>,
{
    fn new(recipient_private_key: &PrivateKey) -> Self;

    fn get_ephemeral_public_key(&self) -> PublicKey;

    fn get_dem_encryptor_be32(&self) -> DecryptorBE32<RustCryptoBackend>;
    fn get_dem_encryptor_le31(&self) -> DecryptorLE31<RustCryptoBackend>;
}
