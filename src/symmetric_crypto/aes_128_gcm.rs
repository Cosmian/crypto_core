//! Implement the `SymmetricCrypto` and `DEM` traits based on the AES 128 GCM
//! algorithm.
//!
//! It will use the AES native interface on the CPU if available.
use super::{
    dem::{DemInPlace, DemStream, Instantiable},
    nonce::Nonce,
};
use crate::{
    symmetric_crypto::{key::SymmetricKey, Dem},
    RandomFixedSizeCBytes,
};
use aead::{generic_array::GenericArray, KeyInit};
use aes_gcm::Aes128Gcm as Aes128GcmLib;
use std::fmt::Debug;

/// Structure implementing `SymmetricCrypto` and the `DEM` interfaces based on
/// AES 128 GCM.
pub struct Aes128Gcm(Aes128GcmLib);

impl Debug for Aes128Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes128Gcm").finish()
    }
}

impl Aes128Gcm {
    /// Use a 128-bit AES key.
    pub const KEY_LENGTH: usize = 16;

    /// Use a 96-bit nonce.
    pub const NONCE_LENGTH: usize = 12;

    /// Use a 128-bit MAC tag.
    pub const MAC_LENGTH: usize = 16;

    /// Plaintext size (in bytes) restriction from the NIST
    /// <https://csrc.nist.gov/publications/detail/sp/800-38d/final>
    pub const MAX_PLAINTEXT_LENGTH: u64 = 68_719_476_704; // (2 ^ 39 - 256) / 8
}

impl Instantiable<{ Aes128Gcm::KEY_LENGTH }> for Aes128Gcm {
    type Secret = SymmetricKey<{ Aes128Gcm::KEY_LENGTH }>;

    fn new(symmetric_key: &Self::Secret) -> Self {
        Self(Aes128GcmLib::new(GenericArray::from_slice(
            symmetric_key.as_bytes(),
        )))
    }
}

impl
    Dem<
        { Aes128Gcm::KEY_LENGTH },
        { Aes128Gcm::NONCE_LENGTH },
        { Aes128Gcm::MAC_LENGTH },
        Aes128GcmLib,
    > for Aes128Gcm
{
    type Nonce = Nonce<{ Aes128Gcm::NONCE_LENGTH }>;

    fn aead_backend<'a>(&'a self) -> &'a Aes128GcmLib {
        &self.0
    }
}

impl
    DemInPlace<
        { Aes128Gcm::KEY_LENGTH },
        { Aes128Gcm::NONCE_LENGTH },
        { Aes128Gcm::MAC_LENGTH },
        Aes128GcmLib,
    > for Aes128Gcm
{
    type Nonce = Nonce<{ Aes128Gcm::NONCE_LENGTH }>;

    fn aead_in_place_backend<'a>(&'a self) -> &'a Aes128GcmLib {
        &self.0
    }
}

impl
    DemStream<
        { Aes128Gcm::KEY_LENGTH },
        { Aes128Gcm::NONCE_LENGTH },
        { Aes128Gcm::MAC_LENGTH },
        Aes128GcmLib,
    > for Aes128Gcm
{
    type Nonce = Nonce<{ Aes128Gcm::NONCE_LENGTH }>;

    fn into_aead_stream_backend(self) -> Aes128GcmLib {
        self.0
    }
}

#[cfg(test)]
mod tests {

    use aead::Payload;

    use crate::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{
            aes_128_gcm::Aes128Gcm,
            dem::{DemStream, Instantiable},
            key::SymmetricKey,
            nonce::Nonce,
            Dem, DemInPlace,
        },
        CryptoCoreError, CsRng, RandomFixedSizeCBytes,
    };

    #[test]
    fn test_dem_combined() -> Result<(), CryptoCoreError> {
        let message = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let nonce = Nonce::new(&mut rng);

        // Encrypt
        let ciphertext = Aes128Gcm::new(&secret_key).encrypt(&nonce, message, additional_data)?;

        // decrypt
        let plaintext =
            Aes128Gcm::new(&secret_key).decrypt(&nonce, &ciphertext, additional_data)?;
        assert_eq!(plaintext, message, "Decryption failed");
        Ok(())
    }

    #[test]
    fn test_dem_in_place() -> Result<(), CryptoCoreError> {
        let message = b"my secret message";
        let additional_data = Some(b"public tag".as_slice());
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let nonce = Nonce::new(&mut rng);

        // the in-place buffer
        let mut buffer = message.to_vec();

        // Encrypt
        let tag = Aes128Gcm::new(&secret_key).encrypt_in_place_detached(
            &nonce,
            &mut buffer,
            additional_data,
        )?;

        // decrypt
        Aes128Gcm::new(&secret_key).decrypt_in_place_detached(
            &nonce,
            &mut buffer,
            &tag,
            additional_data,
        )?;
        assert_eq!(&message[..], buffer.as_slice(), "Decryption failed");
        Ok(())
    }

    #[test]
    fn test_stream_be32() -> Result<(), CryptoCoreError> {
        let message = b"Hello, World!";
        let aad = b"the aad";
        // there will be 2 chunks for the message, one of size 8 and one of size 5
        const BLOCK_SIZE: usize = 8;

        // generate a random key and nonce
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let nonce = Nonce::new(&mut rng);

        // Instantiate an encryptor
        let mut encryptor = Aes128Gcm::new(&secret_key).into_stream_encryptor_be32(&nonce);

        // encrypt the first chunk
        let mut ciphertext = encryptor.encrypt_next(Payload {
            msg: &message[..BLOCK_SIZE],
            aad,
        })?;

        // encrypt the second and last chunk
        ciphertext.extend_from_slice(&encryptor.encrypt_last(Payload {
            msg: &message[BLOCK_SIZE..],
            aad,
        })?);

        // decryption

        // Instantiate a decryptor
        let mut decryptor = Aes128Gcm::new(&secret_key).into_stream_decryptor_be32(&nonce);

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[..BLOCK_SIZE + Aes128Gcm::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[BLOCK_SIZE + Aes128Gcm::MAC_LENGTH..],
            aad,
        })?);

        assert_eq!(
            message.as_slice(),
            plaintext.as_slice(),
            "Decryption failed"
        );
        Ok(())
    }

    #[test]
    fn test_stream_le31() -> Result<(), CryptoCoreError> {
        let message = b"Hello, World!";
        let aad = b"the aad";
        // there will be 2 chunks for the message, one of size 8 and one of size 5
        const BLOCK_SIZE: usize = 8;

        // generate a random key and nonce
        let mut rng = CsRng::from_entropy();
        let secret_key = SymmetricKey::new(&mut rng);
        let nonce = Nonce::new(&mut rng);

        // Instantiate an encryptor
        let mut encryptor = Aes128Gcm::new(&secret_key).into_stream_encryptor_le31(&nonce);

        // encrypt the first chunk
        let mut ciphertext = encryptor.encrypt_next(Payload {
            msg: &message[..BLOCK_SIZE],
            aad,
        })?;

        // encrypt the second and last chunk
        ciphertext.extend_from_slice(&encryptor.encrypt_last(Payload {
            msg: &message[BLOCK_SIZE..],
            aad,
        })?);

        // decryption

        // Instantiate a decryptor
        let mut decryptor = Aes128Gcm::new(&secret_key).into_stream_decryptor_le31(&nonce);

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[..BLOCK_SIZE + Aes128Gcm::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[BLOCK_SIZE + Aes128Gcm::MAC_LENGTH..],
            aad,
        })?);

        assert_eq!(
            message.as_slice(),
            plaintext.as_slice(),
            "Decryption failed"
        );
        Ok(())
    }
}
