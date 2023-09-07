#[cfg(all(
    feature = "ecies",
    feature = "chacha",
    feature = "blake",
    feature = "curve25519"
))]
pub fn ecies_x25519_xchacha20_combined() {
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng, CsRng, Ecies, EciesX25519XChaCha20, X25519PrivateKey,
        X25519PublicKey,
    };

    // A cryptographic random number generator
    let mut rng = CsRng::from_entropy();

    // Generate a key pair
    let private_key = X25519PrivateKey::new(&mut rng);
    let public_key = X25519PublicKey::from(&private_key);

    // The plain text to encrypt
    let plaintext = b"Hello, World!";

    // Some optional authenticated data for theDEM scheme
    let authenticated_data = b"Optional authenticated data";

    // Encrypt the message with the public key using ECIES X25519 XChaCha20
    let ciphertext =
        EciesX25519XChaCha20::encrypt(&mut rng, &public_key, plaintext, Some(authenticated_data))
            .unwrap();

    // Decrypt the message using the private key
    let plaintext_ =
        EciesX25519XChaCha20::decrypt(&private_key, &ciphertext, Some(authenticated_data)).unwrap();

    // Check if the decrypted message is the same as the original message
    assert_eq!(plaintext, &plaintext_[..]);

    println!("ECIES vector X25519 XChaCha20: OK");
}

#[cfg(all(
    feature = "ecies",
    feature = "aes",
    feature = "sha3",
    feature = "nist_curves"
))]
pub fn ecies_p256_aes128_combined() {
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng, CsRng, Ecies, EciesP256Aes128, P256PrivateKey,
        P256PublicKey,
    };

    // A cryptographic random number generator
    let mut rng = CsRng::from_entropy();

    // Generate a key pair
    let private_key = P256PrivateKey::new(&mut rng);
    let public_key = P256PublicKey::from(&private_key);

    // The plain text to encrypt
    let plaintext = b"Hello, World!";

    // Some optional authenticated data for theDEM scheme
    let authenticated_data = b"Optional authenticated data";

    // Encrypt the message with the public key using ECIES X25519 XChaCha20
    let ciphertext =
        EciesP256Aes128::encrypt(&mut rng, &public_key, plaintext, Some(authenticated_data))
            .unwrap();

    // Decrypt the message using the private key
    let plaintext_ =
        EciesP256Aes128::decrypt(&private_key, &ciphertext, Some(authenticated_data)).unwrap();

    // Check if the decrypted message is the same as the original message
    assert_eq!(plaintext, &plaintext_[..]);

    println!("ECIES vector P256 Aes128: OK");
}

#[cfg(all(
    feature = "ecies",
    feature = "chacha",
    feature = "blake",
    feature = "curve25519"
))]
pub fn ecies_x25519_xchacha20_stream() {
    use aead::Payload;
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng, CsRng, EciesStream, EciesX25519XChaCha20,
        FixedSizeCBytes, X25519PrivateKey, X25519PublicKey, XChaCha20Poly1305,
    };

    // generate a random key and nonce
    let mut rng = CsRng::from_entropy();

    // generate a key pair
    let private_key = X25519PrivateKey::new(&mut rng);
    let public_key = X25519PublicKey::from(&private_key);

    // The plain text to encrypt
    let message = b"Hello, World!";

    // Some optional authenticated data for theDEM scheme
    let authenticated_data = b"Optional authenticated data";

    // there will be 2 chunks for the message, one of size 8 and one of size 5
    const BLOCK_SIZE: usize = 8;

    let (ephemeral_public_key, mut encryptor) =
        EciesX25519XChaCha20::get_dem_encryptor_be32(&mut rng, &public_key).unwrap();

    // prepend the ciphertext with the ephemeral public key
    let mut ciphertext = ephemeral_public_key.to_bytes().to_vec();

    // encrypt the first chunk
    ciphertext.extend(
        encryptor
            .encrypt_next(Payload {
                msg: &message[..BLOCK_SIZE],
                aad: authenticated_data,
            })
            .unwrap(),
    );

    // encrypt the second and last chunk
    ciphertext.extend_from_slice(
        &encryptor
            .encrypt_last(Payload {
                msg: &message[BLOCK_SIZE..],
                aad: authenticated_data,
            })
            .unwrap(),
    );

    // decryption

    //recover the ephemeral public key from the ciphertext
    let ephemeral_public_key =
        X25519PublicKey::try_from_slice(&ciphertext[..X25519PublicKey::LENGTH]).unwrap();

    // Instantiate a decryptor
    let mut decryptor =
        EciesX25519XChaCha20::get_dem_decryptor_be32(&private_key, &ephemeral_public_key).unwrap();

    // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
    let mut plaintext = decryptor
        .decrypt_next(Payload {
            msg: &ciphertext[X25519PublicKey::LENGTH
                ..X25519PublicKey::LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH],
            aad: authenticated_data,
        })
        .unwrap();

    // decrypt the second and last chunk
    plaintext.extend_from_slice(
        &decryptor
            .decrypt_last(Payload {
                msg: &ciphertext
                    [X25519PublicKey::LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH..],
                aad: authenticated_data,
            })
            .unwrap(),
    );

    assert_eq!(
        message.as_slice(),
        plaintext.as_slice(),
        "Decryption failed"
    );

    println!("ECIES Stream X25519 XChaCha20: OK");
}

#[cfg(all(
    feature = "ecies",
    feature = "aes",
    feature = "sha3",
    feature = "nist_curves"
))]
pub fn ecies_p256_aes128_stream() {
    use aead::Payload;
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng, CsRng, EciesP256Aes128, EciesStream, FixedSizeCBytes,
        P256PrivateKey, P256PublicKey, XChaCha20Poly1305,
    };

    // generate a random key and nonce
    let mut rng = CsRng::from_entropy();

    // generate a key pair
    let private_key = P256PrivateKey::new(&mut rng);
    let public_key = P256PublicKey::from(&private_key);

    // The plain text to encrypt
    let message = b"Hello, World!";

    // Some optional authenticated data for theDEM scheme
    let authenticated_data = b"Optional authenticated data";

    // there will be 2 chunks for the message, one of size 8 and one of size 5
    const BLOCK_SIZE: usize = 8;

    let (ephemeral_public_key, mut encryptor) =
        EciesP256Aes128::get_dem_encryptor_be32(&mut rng, &public_key).unwrap();

    // prepend the ciphertext with the ephemeral public key
    let mut ciphertext = ephemeral_public_key.to_bytes().to_vec();

    // encrypt the first chunk
    ciphertext.extend(
        encryptor
            .encrypt_next(Payload {
                msg: &message[..BLOCK_SIZE],
                aad: authenticated_data,
            })
            .unwrap(),
    );

    // encrypt the second and last chunk
    ciphertext.extend_from_slice(
        &encryptor
            .encrypt_last(Payload {
                msg: &message[BLOCK_SIZE..],
                aad: authenticated_data,
            })
            .unwrap(),
    );

    // decryption

    //recover the ephemeral public key from the ciphertext
    let ephemeral_public_key =
        P256PublicKey::try_from_slice(&ciphertext[..P256PublicKey::LENGTH]).unwrap();

    // Instantiate a decryptor
    let mut decryptor =
        EciesP256Aes128::get_dem_decryptor_be32(&private_key, &ephemeral_public_key).unwrap();

    // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
    let mut plaintext = decryptor
        .decrypt_next(Payload {
            msg: &ciphertext[P256PublicKey::LENGTH
                ..P256PublicKey::LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH],
            aad: authenticated_data,
        })
        .unwrap();

    // decrypt the second and last chunk
    plaintext.extend_from_slice(
        &decryptor
            .decrypt_last(Payload {
                msg: &ciphertext
                    [P256PublicKey::LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH..],
                aad: authenticated_data,
            })
            .unwrap(),
    );

    assert_eq!(
        message.as_slice(),
        plaintext.as_slice(),
        "Decryption failed"
    );

    println!("ECIES Stream P256 Aes128: OK");
}
