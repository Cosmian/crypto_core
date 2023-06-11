//! These examples are restated in the README.md file

/// Demonstrates how to use symmetric encryption in combined mode
/// where
///  - the plaintext is encrypted as a single block and the
///  - ciphertext is generated inside a newly allocated vector
///    that combines the encrypted data and the MAC
pub fn dem_block_combined() {
    use cosmian_crypto_core::XChaCha20Poly1305;
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng, CsRng, Dem, FixedSizeCBytes, Instantiable, Nonce,
        RandomFixedSizeCBytes, SymmetricKey,
    };

    // Choose one of these DEMs depending on your use case
    // type SC = Aes128Gcm;
    // type SC = Aes256Gcm;
    // type SC = ChaCha20Poly1305;
    type SC = XChaCha20Poly1305;

    // A cryptographically secure random generator
    let mut rng = CsRng::from_entropy();

    // the message to encrypt
    let message = b"my secret message";
    // the secret key used to encrypt the message
    // which is shared between the sender and the recipient
    let secret_key = SymmetricKey::new(&mut rng);

    // the additional data shared between the sender and the recipient to authenticate the message
    let additional_data = Some(b"additional data".as_slice());

    // the sender generate a Nonce and encrypts the message
    let nonce = Nonce::new(&mut rng);
    let dem = SC::new(&secret_key);
    let ciphertext = dem.encrypt(&nonce, message, additional_data).unwrap();

    // to transmit the message, the sender can concatenate the nonce and the ciphertext
    // and send the concatenated result to the recipient
    let ciphertext = [nonce.as_bytes(), ciphertext.as_slice()].concat();

    // the ciphertext size is the message size plus the nonce size plus the authentication tag size
    assert_eq!(
        ciphertext.len(),
        message.len() + SC::NONCE_LENGTH + SC::MAC_LENGTH
    );

    // the recipient extracts the nonce and decrypts the message
    let nonce = Nonce::try_from_slice(&ciphertext[..SC::NONCE_LENGTH]).unwrap();
    let dem = SC::new(&secret_key);
    let plaintext = dem
        .decrypt(&nonce, &ciphertext[SC::NONCE_LENGTH..], additional_data)
        .unwrap();

    // assert the decrypted message is identical to the original plaintext
    assert_eq!(plaintext, message, "Decryption failed");

    println!("{dem:?} block combined SUCCESS");
}

/// Demonstrates how to use symmetric encryption
/// with a stream of data
pub fn dem_stream_be32() {
    use cosmian_crypto_core::XChaCha20Poly1305;
    use cosmian_crypto_core::{
        reexport::{aead::Payload, rand_core::SeedableRng},
        CsRng, DemStream, Instantiable, Nonce, RandomFixedSizeCBytes, SymmetricKey,
    };

    // Choose one of these streaming DEMs depending on your use case
    // type SC = Aes128Gcm;
    // type SC = Aes256Gcm;
    // type SC = ChaCha20Poly1305;
    type SC = XChaCha20Poly1305;

    let message = b"Hello, World!";

    // The message will be encrypted in 2 chunks, one of size 8 and one of size 5
    // In real life, the block size should be much larger and typically a multiple of 4096
    const BLOCK_SIZE: usize = 8;

    // use some additional data to authenticate the message
    let aad = b"the aad";

    // generate a random key and nonce
    let mut rng = CsRng::from_entropy();
    let secret_key = SymmetricKey::new(&mut rng);
    let nonce = Nonce::new(&mut rng);

    // Instantiate a streaming encryptor
    // Two streaming encryptor are available: EncryptorBE32 and EncryptorLE31
    // Check the documentation of the DemStream trait for more details
    let mut encryptor = SC::new(&secret_key).into_stream_encryptor_be32(&nonce);

    // encrypt the first chunk
    let mut ciphertext = encryptor
        .encrypt_next(Payload {
            msg: &message[..BLOCK_SIZE],
            aad,
        })
        .unwrap();

    // encrypt the second and last chunk
    ciphertext.extend_from_slice(
        &encryptor
            .encrypt_last(Payload {
                msg: &message[BLOCK_SIZE..],
                aad,
            })
            .unwrap(),
    );

    // decryption

    // Instantiate a streaming decryptor
    let mut decryptor = SC::new(&secret_key).into_stream_decryptor_be32(&nonce);

    // decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
    let mut plaintext = decryptor
        .decrypt_next(Payload {
            msg: &ciphertext[..BLOCK_SIZE + SC::MAC_LENGTH],
            aad,
        })
        .unwrap();

    // decrypt the second and last chunk
    plaintext.extend_from_slice(
        &decryptor
            .decrypt_last(Payload {
                msg: &ciphertext[BLOCK_SIZE + SC::MAC_LENGTH..],
                aad,
            })
            .unwrap(),
    );

    assert_eq!(
        message.as_slice(),
        plaintext.as_slice(),
        "Decryption failed"
    );

    println!("Streaming DEM SUCCESS");
}
