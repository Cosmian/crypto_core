use aes_gcm::Aes128Gcm as Aes128GcmLib;

use super::ecies_traits::EciesStream;
use crate::{
    asymmetric_crypto::{R25519PrivateKey, R25519PublicKey},
    kdf128,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{Aes128Gcm, Dem, DemStream, Instantiable, Nonce, SymmetricKey},
    CryptoCoreError, Ecies, FixedSizeCBytes, RandomFixedSizeCBytes,
};

/// A thread safe Elliptic Curve Integrated Encryption Scheme (ECIES) using
///  - the Ristretto group of Curve 25519
///  - AES 128 GCM
///  - SHAKE256 (XOF)
pub struct EciesR25519Aes128 {}

fn get_nonce<const NONCE_LENGTH: usize>(
    ephemeral_pk: &R25519PublicKey,
    recipient_pk: &R25519PublicKey,
) -> Nonce<NONCE_LENGTH> {
    let mut nonce = Nonce([0; NONCE_LENGTH]);
    kdf128!(
        &mut nonce.0,
        &ephemeral_pk.to_bytes(),
        &recipient_pk.to_bytes()
    );
    nonce
}

fn get_ephemeral_key<const KEY_LENGTH: usize>(
    shared_point: &R25519PublicKey,
) -> SymmetricKey<KEY_LENGTH> {
    let mut key = SymmetricKey([0; KEY_LENGTH]);
    kdf128!(&mut key.0, &shared_point.to_bytes());
    key
}

impl EciesR25519Aes128 {
    fn generate_keys_and_nonce<R: CryptoRngCore>(
        rng: &mut R,
        recipient_pk: &R25519PublicKey,
    ) -> Result<
        (
            R25519PublicKey,
            SymmetricKey<{ Aes128Gcm::KEY_LENGTH }>,
            Nonce<{ Aes128Gcm::NONCE_LENGTH }>,
        ),
        CryptoCoreError,
    > {
        let ephemeral_sk = R25519PrivateKey::new(rng);
        let ephemeral_pk = R25519PublicKey::from(&ephemeral_sk);

        // Calculate the shared secret point (Px, Py) = P = r.Y
        let shared_point = recipient_pk * &ephemeral_sk;

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256
        // eXtendable-Output-Function (XOF) such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<{ Aes128Gcm::KEY_LENGTH }>(&shared_point);

        // Calculate the nonce based on the 2 public keys
        let nonce = get_nonce::<{ Aes128Gcm::NONCE_LENGTH }>(&ephemeral_pk, recipient_pk);

        Ok((ephemeral_pk, key, nonce))
    }

    fn recover_key_and_nonce(
        recipient_sk: &R25519PrivateKey,
        ephemeral_public_key: &R25519PublicKey,
    ) -> Result<
        (
            SymmetricKey<{ Aes128Gcm::KEY_LENGTH }>,
            Nonce<{ Aes128Gcm::NONCE_LENGTH }>,
        ),
        CryptoCoreError,
    > {
        // Calculate the shared secret point (Px, Py) = P = R.y = r.G.y = r.Y
        let shared_point = ephemeral_public_key * recipient_sk;

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256 XOF
        // such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<{ Aes128Gcm::KEY_LENGTH }>(&shared_point);

        // Recompute the nonce
        let nonce = get_nonce::<{ Aes128Gcm::NONCE_LENGTH }>(
            ephemeral_public_key,
            &R25519PublicKey::from(recipient_sk),
        );

        Ok((key, nonce))
    }
}

impl Ecies<R25519PrivateKey, R25519PublicKey> for EciesR25519Aes128 {
    const ENCRYPTION_OVERHEAD: usize = R25519PublicKey::LENGTH + Aes128Gcm::MAC_LENGTH;

    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        recipient_pk: &R25519PublicKey,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        let (ephemeral_pk, key, nonce) = Self::generate_keys_and_nonce(rng, recipient_pk)
            .map_err(|_| CryptoCoreError::EncryptionError)?;

        // Encrypt and authenticate the message, returning the ciphertext and MAC
        let ciphertext_plus_tag =
            Aes128Gcm::new(&key).encrypt(&nonce, plaintext, authentication_data)?;

        // Assemble the final encrypted message: R || nonce || c || d
        let mut res =
            Vec::with_capacity(R25519PublicKey::LENGTH + plaintext.len() + Aes128Gcm::MAC_LENGTH);
        res.extend(ephemeral_pk.to_bytes());
        res.extend(&ciphertext_plus_tag);

        Ok(res)
    }

    fn decrypt(
        recipient_sk: &R25519PrivateKey,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        // Extract the sender's ephemeral public key R from the ciphertext
        let ephemeral_pk = R25519PublicKey::try_from_slice(&ciphertext[..R25519PublicKey::LENGTH])?;

        // Recover the key and nonce
        let (key, nonce) = Self::recover_key_and_nonce(recipient_sk, &ephemeral_pk)?;

        // Decrypt and verify the message using AES-128-GCM
        let decrypted_message = Aes128Gcm::new(&key).decrypt(
            &nonce,
            &ciphertext[R25519PublicKey::LENGTH..],
            authentication_data,
        )?;

        Ok(decrypted_message)
    }
}

impl EciesStream<R25519PrivateKey, R25519PublicKey, Aes128GcmLib> for EciesR25519Aes128 {
    fn get_dem_encryptor_be32<R: CryptoRngCore>(
        rng: &mut R,
        recipient_public_key: &R25519PublicKey,
    ) -> Result<(R25519PublicKey, aead::stream::EncryptorBE32<Aes128GcmLib>), CryptoCoreError> {
        let (ephemeral_pk, key, nonce) = Self::generate_keys_and_nonce(rng, recipient_public_key)?;
        let aes_128_gcm = Aes128Gcm::new(&key);
        let encryptor = aes_128_gcm.into_stream_encryptor_be32(&nonce);
        Ok((ephemeral_pk, encryptor))
    }

    fn get_dem_encryptor_le31<R: CryptoRngCore>(
        rng: &mut R,
        recipient_public_key: &R25519PublicKey,
    ) -> Result<(R25519PublicKey, aead::stream::EncryptorLE31<Aes128GcmLib>), CryptoCoreError> {
        let (ephemeral_pk, key, nonce) = Self::generate_keys_and_nonce(rng, recipient_public_key)?;
        let aes_128_gcm = Aes128Gcm::new(&key);
        let encryptor = aes_128_gcm.into_stream_encryptor_le31(&nonce);
        Ok((ephemeral_pk, encryptor))
    }

    fn get_dem_decryptor_be32(
        recipient_private_key: &R25519PrivateKey,
        ephemeral_public_key: &R25519PublicKey,
    ) -> Result<aead::stream::DecryptorBE32<Aes128GcmLib>, CryptoCoreError> {
        // recover the symmetric key and nonce
        let (key, nonce) =
            Self::recover_key_and_nonce(recipient_private_key, ephemeral_public_key)?;
        // instantiate the symmetric cipher
        let aes_128_gcm = Aes128Gcm::new(&key);
        // turn it into a stream decryptor
        Ok(aes_128_gcm.into_stream_decryptor_be32(&nonce))
    }

    fn get_dem_decryptor_le31(
        recipient_private_key: &R25519PrivateKey,
        ephemeral_public_key: &R25519PublicKey,
    ) -> Result<aead::stream::DecryptorLE31<Aes128GcmLib>, CryptoCoreError> {
        // recover the symmetric key and nonce
        let (key, nonce) =
            Self::recover_key_and_nonce(recipient_private_key, ephemeral_public_key)?;
        // instantiate the symmetric cipher
        let aes_128_gcm = Aes128Gcm::new(&key);
        // turn it into a stream decryptor
        Ok(aes_128_gcm.into_stream_decryptor_le31(&nonce))
    }
}

#[cfg(test)]
mod tests {
    use aead::Payload;

    use super::CryptoCoreError;
    use crate::{
        asymmetric_crypto::{R25519PrivateKey, R25519PublicKey},
        ecies::{ecies_ristretto_aes128gcm::EciesR25519Aes128, ecies_traits::EciesStream},
        reexport::rand_core::SeedableRng,
        symmetric_crypto::Aes128Gcm,
        CsRng, Ecies, FixedSizeCBytes, RandomFixedSizeCBytes,
    };

    #[test]
    fn ecies_r25519_aes128_gcm_test() {
        let mut rng = CsRng::from_entropy();
        // generate a key pair
        let private_key = R25519PrivateKey::new(&mut rng);
        let public_key = R25519PublicKey::from(&private_key);
        // encrypt
        let plaintext = b"Hello World!";
        let ciphertext =
            EciesR25519Aes128::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
        // check the size is the expected size
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + EciesR25519Aes128::ENCRYPTION_OVERHEAD
        );
        // decrypt
        let plaintext_ = EciesR25519Aes128::decrypt(&private_key, &ciphertext, None).unwrap();
        // assert
        assert_eq!(plaintext, &plaintext_[..]);
    }

    #[test]
    fn test_encrypt_decrypt_with_authenticated_data() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let private_key = R25519PrivateKey::new(&mut rng);
        let public_key = R25519PublicKey::from(&private_key);
        let plaintext = b"Hello, World!";
        let authenticated_data = b"Optional authenticated data";

        // Encrypt the message
        let ciphertext =
            EciesR25519Aes128::encrypt(&mut rng, &public_key, plaintext, Some(authenticated_data))?;

        // Decrypt the message
        let plaintext_ =
            EciesR25519Aes128::decrypt(&private_key, &ciphertext, Some(authenticated_data))?;

        // Check if the decrypted message is the same as the original message
        assert_eq!(plaintext, &plaintext_[..]);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_with_corrupted_authentication_data() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let private_key = R25519PrivateKey::new(&mut rng);
        let public_key = R25519PublicKey::from(&private_key);
        let plaintext = b"Hello, World!";
        let authenticated_data = b"Optional authenticated data";

        // Encrypt the message
        let ciphertext =
            EciesR25519Aes128::encrypt(&mut rng, &public_key, plaintext, Some(authenticated_data))?;

        // Decrypt the message
        let not_decrypted = EciesR25519Aes128::decrypt(
            &private_key,
            &ciphertext,
            Some(&b"Corrupted authenticated data"[..]),
        );

        println!("{not_decrypted:?}");

        assert!(matches!(
            not_decrypted,
            Err(CryptoCoreError::DecryptionError)
        ));

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

        // generate a key pair
        let private_key = R25519PrivateKey::new(&mut rng);
        let public_key = R25519PublicKey::from(&private_key);

        let (ephemeral_public_key, mut encryptor) =
            EciesR25519Aes128::get_dem_encryptor_be32(&mut rng, &public_key)?;

        // prepend the ciphertext with the ephemeral public key
        let mut ciphertext = ephemeral_public_key.to_bytes().to_vec();

        // encrypt the first chunk
        ciphertext.extend(encryptor.encrypt_next(Payload {
            msg: &message[..BLOCK_SIZE],
            aad,
        })?);

        // encrypt the second and last chunk
        ciphertext.extend_from_slice(&encryptor.encrypt_last(Payload {
            msg: &message[BLOCK_SIZE..],
            aad,
        })?);

        // decryption

        //recover the ephemeral public key from the ciphertext
        let ephemeral_public_key =
            R25519PublicKey::try_from_slice(&ciphertext[..R25519PublicKey::LENGTH])?;

        // Instantiate a decryptor
        let mut decryptor =
            EciesR25519Aes128::get_dem_decryptor_be32(&private_key, &ephemeral_public_key)?;

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[R25519PublicKey::LENGTH
                ..R25519PublicKey::LENGTH + BLOCK_SIZE + Aes128Gcm::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[R25519PublicKey::LENGTH + BLOCK_SIZE + Aes128Gcm::MAC_LENGTH..],
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

        // generate a key pair
        let private_key = R25519PrivateKey::new(&mut rng);
        let public_key = R25519PublicKey::from(&private_key);

        let (ephemeral_public_key, mut encryptor) =
            EciesR25519Aes128::get_dem_encryptor_le31(&mut rng, &public_key)?;

        // prepend the ciphertext with the ephemeral public key
        let mut ciphertext = ephemeral_public_key.to_bytes().to_vec();

        // encrypt the first chunk
        ciphertext.extend(encryptor.encrypt_next(Payload {
            msg: &message[..BLOCK_SIZE],
            aad,
        })?);

        // encrypt the second and last chunk
        ciphertext.extend_from_slice(&encryptor.encrypt_last(Payload {
            msg: &message[BLOCK_SIZE..],
            aad,
        })?);

        // decryption

        //recover the ephemeral public key from the ciphertext
        let ephemeral_public_key =
            R25519PublicKey::try_from_slice(&ciphertext[..R25519PublicKey::LENGTH])?;

        // Instantiate a decryptor
        let mut decryptor =
            EciesR25519Aes128::get_dem_decryptor_le31(&private_key, &ephemeral_public_key)?;

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[R25519PublicKey::LENGTH
                ..R25519PublicKey::LENGTH + BLOCK_SIZE + Aes128Gcm::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[R25519PublicKey::LENGTH + BLOCK_SIZE + Aes128Gcm::MAC_LENGTH..],
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
