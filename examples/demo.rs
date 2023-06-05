//! This demo is used in `README.md`.

pub fn aes128gcm() {
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{aes_128_gcm::Aes128Gcm, key::SymmetricKey, Dem},
        CsRng, SecretKey,
    };

    // The cryptographic random generator
    let mut rng = CsRng::from_entropy();

    // the message to encrypt
    let message = b"my secret message";

    // the additional data to authenticate
    let additional_data = Some(b"additional data".as_slice());

    // the secret key used to encrypt the message
    // which is shared between the sender and the recipient
    let secret_key = SymmetricKey::new(&mut rng);

    // the sender encrypts the message
    let ciphertext = Aes128Gcm::encrypt(&mut rng, &secret_key, message, additional_data).unwrap();

    // the recipient decrypts the message
    let plaintext = Aes128Gcm::decrypt(&secret_key, &ciphertext, additional_data).unwrap();

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
