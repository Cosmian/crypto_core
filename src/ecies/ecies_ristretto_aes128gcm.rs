use crate::{
    asymmetric_crypto::{R25519PrivateKey, R25519PublicKey},
    kdf128,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{Aes128Gcm, Dem, Instantiable, Nonce, SymmetricKey},
    CryptoCoreError, Ecies, FixedSizeCBytes, RandomFixedSizeCBytes,
};

/// A thread safe Elliptic Curve Integrated Encryption Scheme (ECIES) using
///  - the Ristretto group of Curve 25516
///  - AES 128 GCM
///  - SHAKE256 (XOF)
pub struct EciesR25519Aes128 {}

#[inline]
fn get_nonce<const NONCE_LENGTH: usize>(
    ephemeral_pk: &R25519PublicKey,
    recipient_pk: &R25519PublicKey,
) -> Nonce<NONCE_LENGTH> {
    Nonce(kdf128!(
        NONCE_LENGTH,
        &ephemeral_pk.to_bytes(),
        &recipient_pk.to_bytes()
    ))
}

#[inline]
fn get_ephemeral_key<const KEY_LENGTH: usize>(
    shared_point: &R25519PublicKey,
) -> SymmetricKey<KEY_LENGTH> {
    SymmetricKey(kdf128!(KEY_LENGTH, &shared_point.to_bytes()))
}

impl Ecies<R25519PrivateKey, R25519PublicKey> for EciesR25519Aes128 {
    const ENCRYPTION_OVERHEAD: usize = R25519PublicKey::LENGTH + Aes128Gcm::MAC_LENGTH;

    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        recipient_pk: &R25519PublicKey,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        let ephemeral_sk = R25519PrivateKey::new(rng);
        let ephemeral_pk = R25519PublicKey::from(&ephemeral_sk);

        // Calculate the shared secret point (Px, Py) = P = r.Y
        let shared_point = recipient_pk * &ephemeral_sk;

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256 eXtendable-Output-Function (XOF)
        // such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<{ Aes128Gcm::KEY_LENGTH }>(&shared_point);

        // Calculate the nonce based on the 2 public keys
        let nonce = get_nonce::<{ Aes128Gcm::NONCE_LENGTH }>(&ephemeral_pk, recipient_pk);

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

        // Calculate the shared secret point (Px, Py) = P = R.y = r.G.y = r.Y
        let shared_point = &ephemeral_pk * recipient_sk;

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256 XOF
        // such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<{ Aes128Gcm::KEY_LENGTH }>(&shared_point);

        // Recompute the nonce
        let nonce = get_nonce::<{ Aes128Gcm::NONCE_LENGTH }>(
            &ephemeral_pk,
            &R25519PublicKey::from(recipient_sk),
        );

        // Decrypt and verify the message using AES-128-GCM
        let decrypted_message = Aes128Gcm::new(&key).decrypt(
            &nonce,
            &ciphertext[R25519PublicKey::LENGTH..],
            authentication_data,
        )?;

        Ok(decrypted_message)
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoCoreError;
    use crate::{
        asymmetric_crypto::{R25519PrivateKey, R25519PublicKey},
        ecies::ecies_ristretto_aes128gcm::EciesR25519Aes128,
        reexport::rand_core::SeedableRng,
        CsRng, Ecies, RandomFixedSizeCBytes,
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

        println!("{:?}", not_decrypted);

        assert!(matches!(
            not_decrypted,
            Err(CryptoCoreError::DecryptionError)
        ));

        Ok(())
    }
}
