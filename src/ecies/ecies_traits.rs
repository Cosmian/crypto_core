use std::ops::Sub;

use aead::{
    consts::{U4, U5},
    generic_array::ArrayLength,
    stream::{DecryptorBE32, DecryptorLE31, EncryptorBE32, EncryptorLE31},
    AeadCore, AeadInPlace, KeyInit,
};

use crate::{reexport::rand_core::CryptoRngCore, CryptoCoreError};

/// Elliptic Curve Integrated Encryption Scheme (ECIES) trait.
///
/// The `Ecies` trait provides methods for encryption and decryption
/// using public-key cryptography based on elliptic curves.
///
/// # Type Parameters
///
/// - `PrivateKey`: the type representing a private key.
/// - `PublicKey`: the type representing a public key.
pub trait Ecies<PrivateKey, PublicKey> {
    /// The size of the overhead added by the encryption process.
    const ENCRYPTION_OVERHEAD: usize;

    /// Encrypts a message using the given public key
    /// and optional authentication data.
    ///
    /// # Note
    ///
    /// Some algorithms, typically the sealed box variants of ECIES,
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
    /// # Note
    ///
    /// Some algorithms, typically the sealed box variants of ECIES,
    /// based on Salsa, do not support authentication data.
    fn decrypt(
        private_key: &PrivateKey,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError>;
}

/// Trait for ECIES stream cipher.
///
/// The `EciesStream` trait provides methods for creating encryptors
/// and decryptors that work with streams of data.
///
/// # Type Parameters
///
/// - `PrivateKey`: the type representing a private key.
/// - `PublicKey`: the type representing a public key.
/// - `RustCryptoBackend`: the `RustCrypto` symmetric cryptographic backend used
///   to perform operations.
pub trait EciesStream<PrivateKey, PublicKey, RustCryptoBackend>
where
    RustCryptoBackend: AeadInPlace + KeyInit,
    <RustCryptoBackend as AeadCore>::NonceSize: Sub<U5>,
    <RustCryptoBackend as AeadCore>::NonceSize: Sub<U4>,
    <<RustCryptoBackend as AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
    <<RustCryptoBackend as AeadCore>::NonceSize as Sub<U4>>::Output: ArrayLength<u8>,
{
    /// Creates a `EncryptorBE32` using the given public key.
    fn get_dem_encryptor_be32<R: CryptoRngCore>(
        rng: &mut R,
        recipient_public_key: &PublicKey,
    ) -> Result<(PublicKey, EncryptorBE32<RustCryptoBackend>), CryptoCoreError>;

    /// Creates a `EncryptorLE31` using the given public key.
    fn get_dem_encryptor_le31<R: CryptoRngCore>(
        rng: &mut R,
        recipient_public_key: &PublicKey,
    ) -> Result<(PublicKey, EncryptorLE31<RustCryptoBackend>), CryptoCoreError>;

    /// Creates a `DecryptorBE32` using the given private key.
    fn get_dem_decryptor_be32(
        recipient_private_key: &PrivateKey,
        ephemeral_public_key: &PublicKey,
    ) -> Result<DecryptorBE32<RustCryptoBackend>, CryptoCoreError>;

    /// Creates a `DecryptorLE31` using the given private key.
    fn get_dem_decryptor_le31(
        recipient_private_key: &PrivateKey,
        ephemeral_public_key: &PublicKey,
    ) -> Result<DecryptorLE31<RustCryptoBackend>, CryptoCoreError>;
}
