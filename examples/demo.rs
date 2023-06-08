//! This demo is used in `README.md`.

use cosmian_crypto_core::{symmetric_crypto::Instantiable, FixedSizeCBytes, RandomFixedSizeCBytes};

pub fn aes128gcm() {
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{Aes128Gcm, Dem, Nonce, SymmetricKey},
        CsRng,
    };

    // A cryptographically secure random generator
    let mut rng = CsRng::from_entropy();

    // the message to encrypt
    let message = b"my secret message";
    // the secret key used to encrypt the message
    // which is shared between the sender and the recipient
    let secret_key = SymmetricKey::new(&mut rng);

    // the additional data shared between the sender and the recipient to authenticate the message
    let additional_data = Some(b"additional data".as_slice());

    // the sender generate a Nonce an encrypts the message
    let nonce = Nonce::new(&mut rng);
    let ciphertext = Aes128Gcm::new(&secret_key)
        .encrypt(&nonce, message, additional_data)
        .unwrap();
    // to transmit the message, the sender can concatenate the nonce and the ciphertext
    // and send the concatenated result to the recipient
    let ciphertext = [nonce.as_bytes(), ciphertext.as_slice()].concat();

    // the ciphertext size is the message size plus the nonce size plus the authentication tag size
    assert_eq!(
        ciphertext.len(),
        message.len() + Aes128Gcm::NONCE_LENGTH + Aes128Gcm::MAC_LENGTH
    );

    // the recipient extracts the nonce and decrypts the message
    let nonce = Nonce::try_from_slice(&ciphertext[..Aes128Gcm::NONCE_LENGTH]).unwrap();
    let plaintext = Aes128Gcm::new(&secret_key)
        .decrypt(
            &nonce,
            &ciphertext[Aes128Gcm::NONCE_LENGTH..],
            additional_data,
        )
        .unwrap();

    // assert the decrypted message is identical to the original plaintext
    assert_eq!(plaintext, message, "Decryption failed");

    println!("AES 128 GCM: SUCCESS");
}

fn main() {
    aes128gcm();
    // // The random generator should be instantiated at the highest possible
    // // level since its creation is relatively costly.
    // let mut rng = CsRng::from_entropy();

    // // Secret message we want to transmit privately.
    // let plaintext = b"My secret message";

    // // Sending an encrypted message using public key cryptography.
    // // The public key of the recipient is used by the sender to encrypt the message.
    // // The recipient uses its private key to decrypt the message.
    // // This example uses the Salsa20 sealed box construction, which is compatible with libsodium sealed box,
    // // see https://doc.libsodium.org/public-key_cryptography/sealed_boxe
    // // and uses X25519 keys as well as the Salsa20 stream cipher.

    // // the recipient generates a secret key
    // let private_key = X25519PrivateKey::new(&mut rng);
    // // and the corresponding public key which it can share with the sender
    // let public_key = X25519PublicKey::from(&private_key);
    // // the sender encrypts the message using the public key of the recipient
    // let ciphertext = EciesSalsaSealBox::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
    // // check the size of the ciphertext is of the expected size
    // assert_eq!(
    //     ciphertext.len(),
    //     plaintext.len() + EciesSalsaSealBox::ENCRYPTION_OVERHEAD
    // );

    // // the recipient decrypts the ciphertext using its private key
    // let plaintext_ = EciesSalsaSealBox::decrypt(&private_key, &ciphertext, None).unwrap();

    // // assert the decrypted message is identical to the original plaintext
    // assert_eq!(plaintext, &plaintext_[..]);

    // // Encrypting a message using symmetric key cryptography.
    // // The sender and the recipient share a secret key.
    // // The sender encrypts the message using the secret key.
    // // The recipient decrypts the message using the secret key.
    // // All the implemented schemes offer the ability to use additional data (AD)
    // // which is authenticated but not encrypted.

    // // This example uses the AES-256-GCM construction, which is compatible with libsodium secret box,
    // // see https://doc.libsodium.org/secret-key_cryptography/secretbox
    // // which uses 256bit symmetric keys and is therefore post-quantum resistant.

    // // the shared secret key between the sender and the recipient
    // let secret_key = SymmetricKey::new(&mut rng);

    // // encrypt the plaintext using the secret key
    // let ciphertext = Aes256Gcm::encrypt(&mut rng, &secret_key, plaintext, None).unwrap();
    // // check the size of the ciphertext is of the expected size
    // assert_eq!(
    //     ciphertext.len(),
    //     plaintext.len() + Aes256Gcm::ENCRYPTION_OVERHEAD
    // );

    // // decrypt the ciphertext using the secret key
    // let plaintext_ = Aes256Gcm::decrypt(&secret_key, &ciphertext, None).unwrap();

    // // assert the decrypted message is identical to the original plaintext
    // assert_eq!(plaintext, &plaintext_[..]);

    // // Success !
    // println!("Success !")
}
