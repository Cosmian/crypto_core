use std::ops::Sub;

use aead::{
    consts::{U4, U5},
    generic_array::ArrayLength,
    stream::{DecryptorBE32, DecryptorLE31, EncryptorBE32, EncryptorLE31},
    AeadCore, AeadInPlace, KeyInit,
};
use rand_core::CryptoRngCore;

use crate::CryptoCoreError;

/// To use with ECIES, Private keys must implement this trait.
/// The only requirement is that their are instantiable from a random value.
pub trait EciesEcPrivateKey<const PRIVATE_KEY_LENGTH: usize> {
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self;
}

/// To use with ECIES, Shared points must implement this trait.
///
/// A Shared Point is the result of the multiplication of a party private key
/// with the other party public key.
///
/// The only requirement is that they can be serialized to a byte array (which
/// will then be hashed)
pub trait EciesEcSharedPoint {
    fn to_vec(&self) -> Vec<u8>;
}

/// To use with ECIES, Public keys must implement this trait.
///
/// Public keys must be serializable and deserializable.
/// They should also be constructible from a [`EciesEcPrivateKey`].
///
/// And the must propose the DH to create a [`EciesEcSharedPoint`]
pub trait EciesEcPublicKey<const PRIVATE_KEY_LENGTH: usize, const PUBLIC_KEY_LENGTH: usize>
where
    Self: Sized,
{
    type PrivateKey: EciesEcPrivateKey<PRIVATE_KEY_LENGTH>;
    type SharedPoint: EciesEcSharedPoint;

    fn from_private_key(private_key: &Self::PrivateKey) -> Self;
    fn try_from_bytes(slice: [u8; PUBLIC_KEY_LENGTH]) -> Result<Self, CryptoCoreError>;
    fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH];
    fn dh(&self, private_key: &Self::PrivateKey) -> Self::SharedPoint;
}

/// Elliptic Curve Integrated Encryption Scheme (ECIES) trait.
///
/// The `Ecies` trait provides methods for encryption and decryption
/// using public-key cryptography based on elliptic curves.
///
/// # Type Parameters
///
/// - `PrivateKey`: the type representing a private key.
/// - `PublicKey`: the type representing a public key.
pub trait Ecies<
    const PRIVATE_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
>
{
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
        private_key: &PublicKey::PrivateKey,
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
pub trait EciesStream<
    const PRIVATE_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    RustCryptoBackend,
> where
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
        recipient_private_key: &PublicKey::PrivateKey,
        ephemeral_public_key: &PublicKey,
    ) -> Result<DecryptorBE32<RustCryptoBackend>, CryptoCoreError>;

    /// Creates a `DecryptorLE31` using the given private key.
    fn get_dem_decryptor_le31(
        recipient_private_key: &PublicKey::PrivateKey,
        ephemeral_public_key: &PublicKey,
    ) -> Result<DecryptorLE31<RustCryptoBackend>, CryptoCoreError>;
}
