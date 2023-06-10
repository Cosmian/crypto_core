//! These examples are restated in the README.md file

/// Demonstrates how to use symmetric encryption in combined mode
/// where the plaintext is encrypted as a single block and the
/// ciphertext is generated inside a newly allocated vector.
pub fn dem_block_combined() {
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{ChaCha20Poly1305, Dem, Instantiable, Nonce, SymmetricKey},
        CsRng, FixedSizeCBytes, RandomFixedSizeCBytes,
    };

    // Choose one of these DEMs depending on your use case
    // type DEM = Aes128Gcm;
    // type DEM = Aes256Gcm;
    type DEM = ChaCha20Poly1305;

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
    let dem = DEM::new(&secret_key);
    let ciphertext = dem.encrypt(&nonce, message, additional_data).unwrap();

    // to transmit the message, the sender can concatenate the nonce and the ciphertext
    // and send the concatenated result to the recipient
    let ciphertext = [nonce.as_bytes(), ciphertext.as_slice()].concat();

    // the ciphertext size is the message size plus the nonce size plus the authentication tag size
    assert_eq!(
        ciphertext.len(),
        message.len() + DEM::NONCE_LENGTH + DEM::MAC_LENGTH
    );

    // the recipient extracts the nonce and decrypts the message
    let nonce = Nonce::try_from_slice(&ciphertext[..DEM::NONCE_LENGTH]).unwrap();
    let dem = DEM::new(&secret_key);
    let plaintext = dem
        .decrypt(&nonce, &ciphertext[DEM::NONCE_LENGTH..], additional_data)
        .unwrap();

    // assert the decrypted message is identical to the original plaintext
    assert_eq!(plaintext, message, "Decryption failed");

    println!("{dem:?} block combined SUCCESS");
}
