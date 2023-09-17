use aead::{consts::U10, generic_array::GenericArray};
use chacha20::hchacha;
use chacha20poly1305::XChaCha20Poly1305 as XChaCha20Poly1305Lib;

use crate::{
    blake2b,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{Dem, DemStream, Instantiable, Nonce, SymmetricKey, XChaCha20Poly1305},
    CryptoCoreError, Ecies, EciesStream, X25519PrivateKey, X25519PublicKey,
    CURVE_25519_SECRET_LENGTH, X25519_PUBLIC_KEY_LENGTH,
};

/// A thread safe Elliptic Curve Integrated Encryption Scheme (ECIES) using
///  - X25519
///  - `XChaCha20`
///  - Blake2b
pub struct EciesX25519XChaCha20 {}

fn get_nonce<const NONCE_LENGTH: usize>(
    ephemeral_pk: &X25519PublicKey,
    recipient_pk: &X25519PublicKey,
) -> Result<Nonce<NONCE_LENGTH>, CryptoCoreError> {
    let mut nonce = Nonce([0; NONCE_LENGTH]);
    blake2b!(nonce.0, ephemeral_pk.as_bytes(), recipient_pk.as_bytes())?;
    Ok(nonce)
}

fn get_ephemeral_key<const KEY_LENGTH: usize>(
    shared_point: &X25519PublicKey,
) -> Result<SymmetricKey<KEY_LENGTH>, CryptoCoreError> {
    let key = hchacha::<U10>(
        GenericArray::from_slice(shared_point.0.as_bytes()),
        &GenericArray::default(),
    );

    Ok(SymmetricKey(key.as_slice().try_into().map_err(|_| {
        CryptoCoreError::InvalidBytesLength("get ephemeral key".to_string(), KEY_LENGTH, None)
    })?))
}

impl EciesX25519XChaCha20 {
    fn generate_keys_and_nonce<R: CryptoRngCore>(
        rng: &mut R,
        recipient_pk: &X25519PublicKey,
    ) -> Result<
        (
            X25519PublicKey,
            SymmetricKey<{ XChaCha20Poly1305::KEY_LENGTH }>,
            Nonce<{ XChaCha20Poly1305::NONCE_LENGTH }>,
        ),
        CryptoCoreError,
    > {
        let ephemeral_sk = X25519PrivateKey::new(rng);
        let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);

        // Calculate the shared secret point (Px, Py) = P = r.Y
        let shared_point = recipient_pk.dh(&ephemeral_sk);

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256
        // eXtendable-Output-Function (XOF) such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<{ XChaCha20Poly1305::KEY_LENGTH }>(&shared_point)?;

        // Calculate the nonce based on the 2 public keys
        let nonce = get_nonce::<{ XChaCha20Poly1305::NONCE_LENGTH }>(&ephemeral_pk, recipient_pk)?;

        Ok((ephemeral_pk, key, nonce))
    }

    fn recover_key_and_nonce(
        recipient_sk: &X25519PrivateKey,
        ephemeral_public_key: &X25519PublicKey,
    ) -> Result<
        (
            SymmetricKey<{ XChaCha20Poly1305::KEY_LENGTH }>,
            Nonce<{ XChaCha20Poly1305::NONCE_LENGTH }>,
        ),
        CryptoCoreError,
    > {
        // Calculate the shared secret point (Px, Py) = P = R.y = r.G.y = r.Y
        let shared_point = ephemeral_public_key.dh(recipient_sk);

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256 XOF
        // such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<{ XChaCha20Poly1305::KEY_LENGTH }>(&shared_point)?;

        // Recompute the nonce
        let nonce = get_nonce::<{ XChaCha20Poly1305::NONCE_LENGTH }>(
            ephemeral_public_key,
            &X25519PublicKey::from(recipient_sk),
        )?;

        Ok((key, nonce))
    }
}

impl Ecies<CURVE_25519_SECRET_LENGTH, X25519_PUBLIC_KEY_LENGTH, X25519PublicKey>
    for EciesX25519XChaCha20
{
    const ENCRYPTION_OVERHEAD: usize = X25519_PUBLIC_KEY_LENGTH + XChaCha20Poly1305::MAC_LENGTH;

    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        recipient_pk: &X25519PublicKey,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        let (ephemeral_pk, key, nonce) = Self::generate_keys_and_nonce(rng, recipient_pk)?;

        // Encrypt and authenticate the message, returning the ciphertext and MAC
        let ciphertext_plus_tag =
            XChaCha20Poly1305::new(&key).encrypt(&nonce, plaintext, authentication_data)?;

        // Assemble the final encrypted message: R || c || d
        let mut res = Vec::with_capacity(
            X25519_PUBLIC_KEY_LENGTH + plaintext.len() + XChaCha20Poly1305::MAC_LENGTH,
        );
        res.extend(ephemeral_pk.to_bytes());
        res.extend(&ciphertext_plus_tag);

        Ok(res)
    }

    fn decrypt(
        recipient_sk: &X25519PrivateKey,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        // Extract the ephemeral public key from the beginning of the ciphertext
        let ephemeral_pk =
            X25519PublicKey::try_from_slice(&ciphertext[..X25519_PUBLIC_KEY_LENGTH])?;

        // recover the symmetric key and nonce
        let (key, nonce) = Self::recover_key_and_nonce(recipient_sk, &ephemeral_pk)?;

        // Decrypt and verify the message using AES-128-GCM
        XChaCha20Poly1305::new(&key).decrypt(
            &nonce,
            &ciphertext[X25519_PUBLIC_KEY_LENGTH..],
            authentication_data,
        )
    }
}

impl
    EciesStream<
        CURVE_25519_SECRET_LENGTH,
        X25519_PUBLIC_KEY_LENGTH,
        X25519PublicKey,
        XChaCha20Poly1305Lib,
    > for EciesX25519XChaCha20
{
    fn get_dem_encryptor_be32<R: CryptoRngCore>(
        rng: &mut R,
        recipient_public_key: &X25519PublicKey,
    ) -> Result<
        (
            X25519PublicKey,
            aead::stream::EncryptorBE32<XChaCha20Poly1305Lib>,
        ),
        CryptoCoreError,
    > {
        let (ephemeral_pk, key, nonce) = Self::generate_keys_and_nonce(rng, recipient_public_key)?;
        let xchacha20 = XChaCha20Poly1305::new(&key);
        let encryptor = xchacha20.into_stream_encryptor_be32(&nonce);
        Ok((ephemeral_pk, encryptor))
    }

    fn get_dem_encryptor_le31<R: CryptoRngCore>(
        rng: &mut R,
        recipient_public_key: &X25519PublicKey,
    ) -> Result<
        (
            X25519PublicKey,
            aead::stream::EncryptorLE31<XChaCha20Poly1305Lib>,
        ),
        CryptoCoreError,
    > {
        let (ephemeral_pk, key, nonce) = Self::generate_keys_and_nonce(rng, recipient_public_key)?;
        let xchacha20 = XChaCha20Poly1305::new(&key);
        let encryptor = xchacha20.into_stream_encryptor_le31(&nonce);
        Ok((ephemeral_pk, encryptor))
    }

    fn get_dem_decryptor_be32(
        recipient_private_key: &X25519PrivateKey,
        ephemeral_public_key: &X25519PublicKey,
    ) -> Result<aead::stream::DecryptorBE32<XChaCha20Poly1305Lib>, CryptoCoreError> {
        // recover the symmetric key and nonce
        let (key, nonce) =
            Self::recover_key_and_nonce(recipient_private_key, ephemeral_public_key)?;
        // instantiate the symmetric cipher
        let xchacha20 = XChaCha20Poly1305::new(&key);
        // turn it into a stream decryptor
        Ok(xchacha20.into_stream_decryptor_be32(&nonce))
    }

    fn get_dem_decryptor_le31(
        recipient_private_key: &X25519PrivateKey,
        ephemeral_public_key: &X25519PublicKey,
    ) -> Result<aead::stream::DecryptorLE31<XChaCha20Poly1305Lib>, CryptoCoreError> {
        // recover the symmetric key and nonce
        let (key, nonce) =
            Self::recover_key_and_nonce(recipient_private_key, ephemeral_public_key)?;
        // instantiate the symmetric cipher
        let xchacha20 = XChaCha20Poly1305::new(&key);
        // turn it into a stream decryptor
        Ok(xchacha20.into_stream_decryptor_le31(&nonce))
    }
}

#[cfg(test)]
mod tests {
    use aead::Payload;

    use super::CryptoCoreError;
    use crate::{
        ecies::traits::EciesStream, reexport::rand_core::SeedableRng,
        symmetric_crypto::XChaCha20Poly1305, CsRng, Ecies, EciesX25519XChaCha20, X25519PrivateKey,
        X25519PublicKey, X25519_PUBLIC_KEY_LENGTH,
    };

    #[test]
    fn ecies_x25519_xchacha20_poly1305_test() {
        let mut rng = CsRng::from_entropy();
        // generate a key pair
        let private_key = X25519PrivateKey::new(&mut rng);
        let public_key = X25519PublicKey::from(&private_key);
        // encrypt
        let plaintext = b"Hello World!";
        let ciphertext =
            EciesX25519XChaCha20::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
        // check the size is the expected size
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + EciesX25519XChaCha20::ENCRYPTION_OVERHEAD
        );
        // decrypt
        let plaintext_ = EciesX25519XChaCha20::decrypt(&private_key, &ciphertext, None).unwrap();
        // assert
        assert_eq!(plaintext, &plaintext_[..]);
    }

    #[test]
    fn test_encrypt_decrypt_with_authenticated_data() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let private_key = X25519PrivateKey::new(&mut rng);
        let public_key = X25519PublicKey::from(&private_key);
        let plaintext = b"Hello, World!";
        let authenticated_data = b"Optional authenticated data";

        // Encrypt the message
        let ciphertext = EciesX25519XChaCha20::encrypt(
            &mut rng,
            &public_key,
            plaintext,
            Some(authenticated_data),
        )?;

        // Decrypt the message
        let plaintext_ =
            EciesX25519XChaCha20::decrypt(&private_key, &ciphertext, Some(authenticated_data))?;

        // Check if the decrypted message is the same as the original message
        assert_eq!(plaintext, &plaintext_[..]);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_with_corrupted_authentication_data() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let private_key = X25519PrivateKey::new(&mut rng);
        let public_key = X25519PublicKey::from(&private_key);
        let plaintext = b"Hello, World!";
        let authenticated_data = b"Optional authenticated data";

        // Encrypt the message
        let ciphertext = EciesX25519XChaCha20::encrypt(
            &mut rng,
            &public_key,
            plaintext,
            Some(authenticated_data),
        )?;

        // Decrypt the message
        let not_decrypted = EciesX25519XChaCha20::decrypt(
            &private_key,
            &ciphertext,
            Some(&b"Corrupted authenticated data"[..]),
        );
        
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
        let private_key = X25519PrivateKey::new(&mut rng);
        let public_key = X25519PublicKey::from(&private_key);

        let (ephemeral_public_key, mut encryptor) =
            EciesX25519XChaCha20::get_dem_encryptor_be32(&mut rng, &public_key)?;

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
            X25519PublicKey::try_from_slice(&ciphertext[..X25519_PUBLIC_KEY_LENGTH])?;

        // Instantiate a decryptor
        let mut decryptor =
            EciesX25519XChaCha20::get_dem_decryptor_be32(&private_key, &ephemeral_public_key)?;

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[X25519_PUBLIC_KEY_LENGTH
                ..X25519_PUBLIC_KEY_LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext
                [X25519_PUBLIC_KEY_LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH..],
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
        let private_key = X25519PrivateKey::new(&mut rng);
        let public_key = X25519PublicKey::from(&private_key);

        let (ephemeral_public_key, mut encryptor) =
            EciesX25519XChaCha20::get_dem_encryptor_le31(&mut rng, &public_key)?;

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
            X25519PublicKey::try_from_slice(&ciphertext[..X25519_PUBLIC_KEY_LENGTH])?;

        // Instantiate a decryptor
        let mut decryptor =
            EciesX25519XChaCha20::get_dem_decryptor_le31(&private_key, &ephemeral_public_key)?;

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext[X25519_PUBLIC_KEY_LENGTH
                ..X25519_PUBLIC_KEY_LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext
                [X25519_PUBLIC_KEY_LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH..],
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
