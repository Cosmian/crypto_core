use crate::{
    asymmetric_crypto::{X25519PrivateKey, X25519PublicKey},
    blake2b,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{Dem, Instantiable, Nonce, SymmetricKey, XChaCha20Poly1305},
    CryptoCoreError, Ecies, FixedSizeCBytes, RandomFixedSizeCBytes,
};

/// A thread safe Elliptic Curve Integrated Encryption Scheme (ECIES) using
///  - X25519
///  - XChaCha20
///  - Blake2b
pub struct EciesX25519XChaCha20 {}

#[inline]
fn get_nonce<const NONCE_LENGTH: usize>(
    ephemeral_pk: &X25519PublicKey,
    recipient_pk: &X25519PublicKey,
) -> Result<Nonce<NONCE_LENGTH>, CryptoCoreError> {
    Ok(Nonce(blake2b!(
        NONCE_LENGTH,
        &ephemeral_pk.to_bytes(),
        &recipient_pk.to_bytes()
    )?))
}

#[inline]
fn get_ephemeral_key<const KEY_LENGTH: usize>(
    shared_point: &X25519PublicKey,
) -> Result<SymmetricKey<KEY_LENGTH>, CryptoCoreError> {
    Ok(SymmetricKey(blake2b!(
        KEY_LENGTH,
        &shared_point.to_bytes()
    )?))
}

impl Ecies<X25519PrivateKey, X25519PublicKey> for EciesX25519XChaCha20 {
    const ENCRYPTION_OVERHEAD: usize = X25519PublicKey::LENGTH + XChaCha20Poly1305::MAC_LENGTH;

    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        recipient_pk: &X25519PublicKey,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        let ephemeral_sk = X25519PrivateKey::new(rng);
        let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);

        // Calculate the shared secret point (Px, Py) = P = r.Y
        let shared_point = recipient_pk * &ephemeral_sk;

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256 eXtendable-Output-Function (XOF)
        // such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<{ XChaCha20Poly1305::KEY_LENGTH }>(&shared_point)?;

        // Calculate the nonce based on the 2 public keys
        let nonce = get_nonce::<{ XChaCha20Poly1305::NONCE_LENGTH }>(&ephemeral_pk, recipient_pk)?;

        // Encrypt and authenticate the message, returning the ciphertext and MAC
        let ciphertext_plus_tag =
            XChaCha20Poly1305::new(&key).encrypt(&nonce, plaintext, authentication_data)?;

        // Assemble the final encrypted message: R || nonce || c || d
        let mut res = Vec::with_capacity(
            X25519PublicKey::LENGTH + plaintext.len() + XChaCha20Poly1305::MAC_LENGTH,
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
        // Extract the sender's ephemeral public key R from the ciphertext
        let ephemeral_pk = X25519PublicKey::try_from_slice(&ciphertext[..X25519PublicKey::LENGTH])?;

        // Calculate the shared secret point (Px, Py) = P = R.y = r.G.y = r.Y
        let shared_point = &ephemeral_pk * recipient_sk;

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256 XOF
        // such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<{ XChaCha20Poly1305::KEY_LENGTH }>(&shared_point)?;

        // Recompute the nonce
        let nonce = get_nonce::<{ XChaCha20Poly1305::NONCE_LENGTH }>(
            &ephemeral_pk,
            &X25519PublicKey::from(recipient_sk),
        )?;

        // Decrypt and verify the message using AES-128-GCM
        let decrypted_message = XChaCha20Poly1305::new(&key).decrypt(
            &nonce,
            &ciphertext[X25519PublicKey::LENGTH..],
            authentication_data,
        )?;

        Ok(decrypted_message)
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoCoreError;
    use crate::{
        asymmetric_crypto::{X25519PrivateKey, X25519PublicKey},
        ecies::EciesX25519XChaCha20,
        reexport::rand_core::SeedableRng,
        CsRng, Ecies, RandomFixedSizeCBytes,
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

        println!("{:?}", not_decrypted);

        assert!(matches!(
            not_decrypted,
            Err(CryptoCoreError::DecryptionError)
        ));

        Ok(())
    }
}
