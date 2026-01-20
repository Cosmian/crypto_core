use aes_gcm::Aes128Gcm as Aes128GcmLib;

use super::traits::EciesStream;
use crate::{
    ecies::traits::{EciesEcPrivateKey, EciesEcPublicKey, EciesEcSharedPoint},
    kdf128,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{Aes128Gcm, Dem, DemStream, Instantiable, Nonce},
    CryptoCoreError, Ecies, SymmetricKey,
};

/// A thread safe Elliptic Curve Integrated Encryption Scheme (ECIES) using
pub struct EciesAes128<
    const PRIVATE_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
> {
    _public_key: std::marker::PhantomData<PublicKey>,
}

fn get_nonce<
    const NONCE_LENGTH: usize,
    const PRIVATE_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
>(
    ephemeral_pk: &PublicKey,
    recipient_pk: &PublicKey,
) -> Nonce<NONCE_LENGTH> {
    let mut nonce = Nonce([0; NONCE_LENGTH]);
    kdf128!(
        &mut nonce.0,
        &ephemeral_pk.to_bytes(),
        &recipient_pk.to_bytes()
    );
    nonce
}

fn get_ephemeral_key<
    const KEY_LENGTH: usize,
    const PRIVATE_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
>(
    shared_point: &PublicKey::SharedPoint,
) -> SymmetricKey<KEY_LENGTH> {
    let mut key = SymmetricKey::default();
    kdf128!(&mut *key, &shared_point.to_vec());
    key
}

impl<
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    > EciesAes128<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>
{
    fn generate_keys_and_nonce<R: CryptoRngCore>(
        rng: &mut R,
        recipient_pk: &PublicKey,
    ) -> Result<
        (
            PublicKey,
            SymmetricKey<{ Aes128Gcm::KEY_LENGTH }>,
            Nonce<{ Aes128Gcm::NONCE_LENGTH }>,
        ),
        CryptoCoreError,
    > {
        let ephemeral_sk = PublicKey::PrivateKey::new(rng);
        let ephemeral_pk = PublicKey::from_private_key(&ephemeral_sk);

        // Calculate the shared secret point (Px, Py) = P = r.Y
        let shared_point = recipient_pk.dh(&ephemeral_sk);

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256
        // eXtendable-Output-Function (XOF) such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<
            { Aes128Gcm::KEY_LENGTH },
            PRIVATE_KEY_LENGTH,
            PUBLIC_KEY_LENGTH,
            PublicKey,
        >(&shared_point);

        // Calculate the nonce based on the 2 public keys
        let nonce = get_nonce::<
            { Aes128Gcm::NONCE_LENGTH },
            PRIVATE_KEY_LENGTH,
            PUBLIC_KEY_LENGTH,
            PublicKey,
        >(&ephemeral_pk, recipient_pk);

        Ok((ephemeral_pk, key, nonce))
    }

    fn recover_key_and_nonce(
        recipient_sk: &PublicKey::PrivateKey,
        ephemeral_pk: &PublicKey,
    ) -> Result<
        (
            SymmetricKey<{ Aes128Gcm::KEY_LENGTH }>,
            Nonce<{ Aes128Gcm::NONCE_LENGTH }>,
        ),
        CryptoCoreError,
    > {
        // Calculate the shared secret point (Px, Py) = P = R.y = r.G.y = r.Y
        let shared_point = ephemeral_pk.dh(recipient_sk);

        // Generate the 128-bit symmetric encryption key k, derived using SHAKE256 XOF
        // such as: k = kdf(S || S1) where:
        // - S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
        // - S1: if the user provided shared_encapsulation_data S1, then we append it to
        //   the shared_bytes S
        // This implementation does NOT use the shared_encapsulation_data S1
        let key = get_ephemeral_key::<
            { Aes128Gcm::KEY_LENGTH },
            PRIVATE_KEY_LENGTH,
            PUBLIC_KEY_LENGTH,
            PublicKey,
        >(&shared_point);

        // Recompute the nonce
        let nonce = get_nonce::<
            { Aes128Gcm::NONCE_LENGTH },
            PRIVATE_KEY_LENGTH,
            PUBLIC_KEY_LENGTH,
            PublicKey,
        >(ephemeral_pk, &PublicKey::from_private_key(recipient_sk));

        Ok((key, nonce))
    }
}

impl<
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    > Ecies<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>
    for EciesAes128<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>
{
    const ENCRYPTION_OVERHEAD: usize = PUBLIC_KEY_LENGTH + Aes128Gcm::MAC_LENGTH;

    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        recipient_pk: &PublicKey,
        plaintext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        let (ephemeral_pk, key, nonce) = Self::generate_keys_and_nonce::<R>(rng, recipient_pk)
            .map_err(|_| CryptoCoreError::EncryptionError)?;

        // Encrypt and authenticate the message, returning the ciphertext and MAC
        let ciphertext_plus_tag =
            Aes128Gcm::new(&key).encrypt(&nonce, plaintext, authentication_data)?;

        // Assemble the final encrypted message: R || nonce || c || d
        let mut res =
            Vec::with_capacity(PUBLIC_KEY_LENGTH + plaintext.len() + Aes128Gcm::MAC_LENGTH);
        res.extend(ephemeral_pk.to_bytes());
        res.extend(&ciphertext_plus_tag);

        Ok(res)
    }

    fn decrypt(
        recipient_sk: &PublicKey::PrivateKey,
        ciphertext: &[u8],
        authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        // Extract the sender's ephemeral public key R from the ciphertext
        let mut byte_array = [0u8; PUBLIC_KEY_LENGTH];
        byte_array.copy_from_slice(&ciphertext[..PUBLIC_KEY_LENGTH]);
        let ephemeral_pk = PublicKey::try_from_bytes(byte_array)?;

        // Recover the key and nonce
        let (key, nonce) = Self::recover_key_and_nonce(recipient_sk, &ephemeral_pk)?;

        // Decrypt and verify the message using AES-128-GCM
        let decrypted_message = Aes128Gcm::new(&key).decrypt(
            &nonce,
            &ciphertext[PUBLIC_KEY_LENGTH..],
            authentication_data,
        )?;

        Ok(decrypted_message)
    }
}

impl<
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    > EciesStream<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey, Aes128GcmLib>
    for EciesAes128<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>
{
    fn get_dem_encryptor_be32<R: CryptoRngCore>(
        rng: &mut R,
        recipient_public_key: &PublicKey,
    ) -> Result<(PublicKey, aead::stream::EncryptorBE32<Aes128GcmLib>), CryptoCoreError> {
        let (ephemeral_pk, key, nonce) =
            Self::generate_keys_and_nonce::<R>(rng, recipient_public_key)?;
        let aes_128_gcm = Aes128Gcm::new(&key);
        let encryptor = aes_128_gcm.into_stream_encryptor_be32(&nonce);
        Ok((ephemeral_pk, encryptor))
    }

    fn get_dem_encryptor_le31<R: CryptoRngCore>(
        rng: &mut R,
        recipient_public_key: &PublicKey,
    ) -> Result<(PublicKey, aead::stream::EncryptorLE31<Aes128GcmLib>), CryptoCoreError> {
        let (ephemeral_pk, key, nonce) =
            Self::generate_keys_and_nonce::<R>(rng, recipient_public_key)?;
        let aes_128_gcm = Aes128Gcm::new(&key);
        let encryptor = aes_128_gcm.into_stream_encryptor_le31(&nonce);
        Ok((ephemeral_pk, encryptor))
    }

    fn get_dem_decryptor_be32(
        recipient_private_key: &PublicKey::PrivateKey,
        ephemeral_public_key: &PublicKey,
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
        recipient_private_key: &PublicKey::PrivateKey,
        ephemeral_public_key: &PublicKey,
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

#[cfg(all(test, feature = "nist_curves", feature = "curve25519"))]
mod tests {
    use aead::Payload;

    use crate::{
        ecies::traits::{EciesEcPrivateKey, EciesEcPublicKey},
        reexport::rand_core::SeedableRng,
        Aes128Gcm, CryptoCoreError, CsRng, Ecies, EciesAes128, EciesStream, P192PublicKey,
        P224PublicKey, P256PublicKey, P384PublicKey, R25519Point, X25519PublicKey,
        CURVE_25519_SECRET_LENGTH, P192_PRIVATE_KEY_LENGTH, P192_PUBLIC_KEY_LENGTH,
        P224_PRIVATE_KEY_LENGTH, P224_PUBLIC_KEY_LENGTH, P256_PRIVATE_KEY_LENGTH,
        P256_PUBLIC_KEY_LENGTH, P384_PRIVATE_KEY_LENGTH, P384_PUBLIC_KEY_LENGTH,
        R25519_POINT_LENGTH, R25519_SCALAR_LENGTH, X25519_PUBLIC_KEY_LENGTH,
    };

    fn test_encrypt_decrypt<
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    >() {
        let mut rng = CsRng::from_entropy();
        // generate a key pair
        let private_key = PublicKey::PrivateKey::new(&mut rng);
        let public_key = PublicKey::from_private_key(&private_key);

        // encrypt
        let plaintext = b"Hello World!";
        let ciphertext = EciesAes128::<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>::encrypt(
            &mut rng,
            &public_key,
            plaintext,
            None,
        )
        .unwrap();
        // check the size is the expected size
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + EciesAes128::<PRIVATE_KEY_LENGTH,PUBLIC_KEY_LENGTH, PublicKey>::ENCRYPTION_OVERHEAD
        );
        // decrypt
        let plaintext_ = EciesAes128::<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>::decrypt(
            &private_key,
            &ciphertext,
            None,
        )
        .unwrap();
        // assert
        assert_eq!(plaintext, &plaintext_[..]);
    }

    fn test_encrypt_decrypt_with_authenticated_data<
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    >() {
        let mut rng = CsRng::from_entropy();
        let authenticated_data = b"Optional authenticated data";
        // generate a key pair
        let private_key = PublicKey::PrivateKey::new(&mut rng);
        let public_key = PublicKey::from_private_key(&private_key);

        // encrypt
        let plaintext = b"Hello World!";
        let ciphertext = EciesAes128::<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>::encrypt(
            &mut rng,
            &public_key,
            plaintext,
            Some(authenticated_data),
        )
        .unwrap();
        // check the size is the expected size
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + EciesAes128::<PRIVATE_KEY_LENGTH,PUBLIC_KEY_LENGTH, PublicKey>::ENCRYPTION_OVERHEAD
        );
        // decrypt
        let plaintext_ = EciesAes128::<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>::decrypt(
            &private_key,
            &ciphertext,
            Some(authenticated_data),
        )
        .unwrap();
        // assert
        assert_eq!(plaintext, &plaintext_[..]);
    }

    fn test_encrypt_decrypt_with_wrong_authenticated_data<
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    >() {
        let mut rng = CsRng::from_entropy();
        let authenticated_data = b"Optional authenticated data";
        // generate a key pair
        let private_key = PublicKey::PrivateKey::new(&mut rng);
        let public_key = PublicKey::from_private_key(&private_key);

        // encrypt
        let plaintext = b"Hello World!";
        let ciphertext = EciesAes128::<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>::encrypt(
            &mut rng,
            &public_key,
            plaintext,
            Some(authenticated_data),
        )
        .unwrap();
        // check the size is the expected size
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + EciesAes128::<PRIVATE_KEY_LENGTH,PUBLIC_KEY_LENGTH, PublicKey>::ENCRYPTION_OVERHEAD
        );
        // decrypt
        let fail = EciesAes128::<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>::decrypt(
            &private_key,
            &ciphertext,
            Some(b"wrong data"),
        );
        // assert
        assert!(fail.is_err());
    }

    fn test_stream_be32<
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    >() -> Result<(), CryptoCoreError> {
        let message = b"Hello, World!";
        let aad = b"the aad";
        // there will be 2 chunks for the message, one of size 8 and one of size 5
        const BLOCK_SIZE: usize = 8;

        // generate a random key and nonce
        let mut rng = CsRng::from_entropy();

        // generate a key pair
        let private_key = PublicKey::PrivateKey::new(&mut rng);
        let public_key = PublicKey::from_private_key(&private_key);

        let (ephemeral_public_key, mut encryptor) = EciesAes128::<
            PRIVATE_KEY_LENGTH,
            PUBLIC_KEY_LENGTH,
            PublicKey,
        >::get_dem_encryptor_be32(
            &mut rng, &public_key
        )?;

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
        let mut byte_array = [0u8; PUBLIC_KEY_LENGTH];
        byte_array.copy_from_slice(&ciphertext[..PUBLIC_KEY_LENGTH]);
        let ephemeral_public_key = PublicKey::try_from_bytes(byte_array)?;

        // Instantiate a decryptor
        let mut decryptor = EciesAes128::<PRIVATE_KEY_LENGTH,PUBLIC_KEY_LENGTH, PublicKey>::get_dem_decryptor_be32(
            &private_key,
            &ephemeral_public_key,
        )?;

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext
                [PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH + BLOCK_SIZE + Aes128Gcm::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[PUBLIC_KEY_LENGTH + BLOCK_SIZE + Aes128Gcm::MAC_LENGTH..],
            aad,
        })?);

        assert_eq!(
            message.as_slice(),
            plaintext.as_slice(),
            "Decryption failed"
        );
        Ok(())
    }

    fn test_stream_le31<
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    >() -> Result<(), CryptoCoreError> {
        let message = b"Hello, World!";
        let aad = b"the aad";
        // there will be 2 chunks for the message, one of size 8 and one of size 5
        const BLOCK_SIZE: usize = 8;

        // generate a random key and nonce
        let mut rng = CsRng::from_entropy();

        // generate a key pair
        let private_key = PublicKey::PrivateKey::new(&mut rng);
        let public_key = PublicKey::from_private_key(&private_key);

        let (ephemeral_public_key, mut encryptor) = EciesAes128::<
            PRIVATE_KEY_LENGTH,
            PUBLIC_KEY_LENGTH,
            PublicKey,
        >::get_dem_encryptor_le31(
            &mut rng, &public_key
        )?;

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
        let mut byte_array = [0u8; PUBLIC_KEY_LENGTH];
        byte_array.copy_from_slice(&ciphertext[..PUBLIC_KEY_LENGTH]);
        let ephemeral_public_key = PublicKey::try_from_bytes(byte_array)?;

        // Instantiate a decryptor
        let mut decryptor = EciesAes128::<PRIVATE_KEY_LENGTH,PUBLIC_KEY_LENGTH, PublicKey>::get_dem_decryptor_le31(
            &private_key,
            &ephemeral_public_key,
        )?;

        // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
        let mut plaintext = decryptor.decrypt_next(Payload {
            msg: &ciphertext
                [PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH + BLOCK_SIZE + Aes128Gcm::MAC_LENGTH],
            aad,
        })?;

        // decrypt the second and last chunk
        plaintext.extend_from_slice(&decryptor.decrypt_last(Payload {
            msg: &ciphertext[PUBLIC_KEY_LENGTH + BLOCK_SIZE + Aes128Gcm::MAC_LENGTH..],
            aad,
        })?);

        assert_eq!(
            message.as_slice(),
            plaintext.as_slice(),
            "Decryption failed"
        );
        Ok(())
    }

    fn all_ecies_tests<
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
        PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
    >() {
        test_encrypt_decrypt::<{ PRIVATE_KEY_LENGTH }, { PUBLIC_KEY_LENGTH }, PublicKey>();
        test_encrypt_decrypt_with_authenticated_data::<
            { PRIVATE_KEY_LENGTH },
            { PUBLIC_KEY_LENGTH },
            PublicKey,
        >();
        test_encrypt_decrypt_with_wrong_authenticated_data::<
            { PRIVATE_KEY_LENGTH },
            { PUBLIC_KEY_LENGTH },
            PublicKey,
        >();
        test_stream_be32::<{ PRIVATE_KEY_LENGTH }, { PUBLIC_KEY_LENGTH }, PublicKey>().unwrap();
        test_stream_le31::<{ PRIVATE_KEY_LENGTH }, { PUBLIC_KEY_LENGTH }, PublicKey>().unwrap();
    }

    #[test]
    fn test_combinations() {
        all_ecies_tests::<{ R25519_SCALAR_LENGTH }, { R25519_POINT_LENGTH }, R25519Point>();
        all_ecies_tests::<
            { CURVE_25519_SECRET_LENGTH },
            { X25519_PUBLIC_KEY_LENGTH },
            X25519PublicKey,
        >();
        all_ecies_tests::<{ P384_PRIVATE_KEY_LENGTH }, { P384_PUBLIC_KEY_LENGTH }, P384PublicKey>();
        all_ecies_tests::<{ P256_PRIVATE_KEY_LENGTH }, { P256_PUBLIC_KEY_LENGTH }, P256PublicKey>();
        all_ecies_tests::<{ P224_PRIVATE_KEY_LENGTH }, { P224_PUBLIC_KEY_LENGTH }, P224PublicKey>();
        all_ecies_tests::<{ P192_PRIVATE_KEY_LENGTH }, { P192_PUBLIC_KEY_LENGTH }, P192PublicKey>();
    }
}
