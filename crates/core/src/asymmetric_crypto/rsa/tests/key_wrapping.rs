use openssl::{
    encrypt::{Decrypter, Encrypter},
    hash::MessageDigest,
    pkey::PKey,
    rsa::Padding,
};
use pkcs8::{DecodePrivateKey, DecodePublicKey};
use zeroize::Zeroizing;

use crate::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng, RsaKeyLength, RsaKeyWrappingAlgorithm, RsaPrivateKey, RsaPublicKey,
};

fn wrap_unwrap(
    rng: &mut CsRng,
    rsa_private_key: &RsaPrivateKey,
    wrapping_algorithm: RsaKeyWrappingAlgorithm,
) {
    let mut msg = [0_u8; 32];
    rng.fill_bytes(&mut msg);

    let mut key_to_wrap = [0_u8; 189];
    rng.fill_bytes(&mut key_to_wrap);
    let key_to_wrap = Zeroizing::from(key_to_wrap.to_vec());

    let rsa_public_key = rsa_private_key.public_key();

    let wrapped_key = rsa_public_key
        .wrap_key(rng, wrapping_algorithm, &key_to_wrap)
        .unwrap();
    assert_eq!(
        rsa_private_key
            .unwrap_key(wrapping_algorithm, &wrapped_key)
            .unwrap(),
        key_to_wrap
    );
}

fn test_all_algos(rng: &mut CsRng, rsa_private_key: &RsaPrivateKey) {
    print!("Pkcs1v1_5...");
    wrap_unwrap(rng, rsa_private_key, RsaKeyWrappingAlgorithm::Pkcs1v1_5);
    println!("ok.");

    print!("OaepSha256...");
    wrap_unwrap(rng, rsa_private_key, RsaKeyWrappingAlgorithm::OaepSha256);
    println!("ok.");

    print!("OaepSha1...");
    wrap_unwrap(rng, rsa_private_key, RsaKeyWrappingAlgorithm::OaepSha1);
    println!("ok.");

    print!("OaepSha3...");
    wrap_unwrap(rng, rsa_private_key, RsaKeyWrappingAlgorithm::OaepSha3);
    println!("ok.");

    print!("Aes256Sha256...");
    wrap_unwrap(rng, rsa_private_key, RsaKeyWrappingAlgorithm::Aes256Sha256);
    println!("ok.");

    print!("Aes256Sha1...");
    wrap_unwrap(rng, rsa_private_key, RsaKeyWrappingAlgorithm::Aes256Sha1);
    println!("ok.");

    print!("Aes256Sha3...");
    wrap_unwrap(rng, rsa_private_key, RsaKeyWrappingAlgorithm::Aes256Sha3);
    println!("ok.");
}

#[test]
fn test_wrap_unwrap() {
    let mut rng = CsRng::from_entropy();
    println!("Generating 3072 bit RSA key...");
    let rsa_private_key = RsaPrivateKey::new(&mut rng, RsaKeyLength::Modulus3072).unwrap();
    test_all_algos(&mut rng, &rsa_private_key);
    println!("Generating 4096 bit RSA key...");
    let rsa_private_key = RsaPrivateKey::new(&mut rng, RsaKeyLength::Modulus4096).unwrap();
    test_all_algos(&mut rng, &rsa_private_key);
    println!("Generating 2048 bit RSA key...");
    let rsa_private_key = RsaPrivateKey::new(&mut rng, RsaKeyLength::Modulus2048).unwrap();
    test_all_algos(&mut rng, &rsa_private_key);
}

#[test]
fn test_openssl_wrap_oaep_sha256_compat() {
    let mut rng = CsRng::from_entropy();

    // load the secret from the disk
    let secret = Zeroizing::from(
        std::fs::read("src/asymmetric_crypto/rsa/tests/openssl/32_byte.key").unwrap(),
    );

    // load the binary file from the disk
    let rsa_public_key_pem = String::from_utf8(
        std::fs::read("src/asymmetric_crypto/rsa/tests/openssl/rsa_3072_bit.pub.pkcs8.pem")
            .unwrap(),
    )
    .unwrap();
    // load the RSA public key from the PEM file
    let rsa_public_key = RsaPublicKey::from_public_key_pem(&rsa_public_key_pem).unwrap();

    let encrypted = rsa_public_key
        .wrap_key(&mut rng, RsaKeyWrappingAlgorithm::OaepSha256, &secret)
        .unwrap();

    // OpenSSL

    // load the binary file from the disk
    let rsa_private_key_pem =
        std::fs::read("src/asymmetric_crypto/rsa/tests/openssl/rsa_3072_bit.key.pkcs8.pem")
            .unwrap();

    let rsa_private_key = PKey::private_key_from_pem(&rsa_private_key_pem).unwrap();
    let mut decrypter = Decrypter::new(&rsa_private_key).unwrap();
    decrypter.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    decrypter.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    decrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();

    // Get the length of the output buffer
    let buffer_len = decrypter.decrypt_len(&encrypted).unwrap();
    let mut decoded = vec![0u8; buffer_len];

    // Decrypt the data and get its length
    let decoded_len = decrypter.decrypt(&encrypted, &mut decoded).unwrap();

    // Use only the part of the buffer with the decrypted data
    let decoded = &decoded[..decoded_len];

    assert_eq!(decoded, &secret[..]);
}

#[test]
fn test_openssl_unwrap_oaep_sha256_compat() {
    // load the secret from the disk
    let secret = Zeroizing::from(
        std::fs::read("src/asymmetric_crypto/rsa/tests/openssl/32_byte.key").unwrap(),
    );

    // openssl

    // load the binary file from the disk
    let rsa_public_key_pem =
        std::fs::read("src/asymmetric_crypto/rsa/tests/openssl/rsa_3072_bit.pub.pkcs8.pem")
            .unwrap();
    let rsa_public_key = PKey::public_key_from_pem(&rsa_public_key_pem).unwrap();

    let mut encrypter = Encrypter::new(&rsa_public_key).unwrap();
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    encrypter.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();

    let buffer_len = encrypter.encrypt_len(&secret).unwrap();
    let mut wrapped_secret = vec![0u8; buffer_len];

    // Encode the data and get its length
    let encoded_len = encrypter.encrypt(&secret, &mut wrapped_secret).unwrap();

    // Use only the part of the buffer with the encoded data
    let wrapped_secret = &wrapped_secret[..encoded_len];

    // crypto-core

    // load the binary file from the disk
    let rsa_private_key_pem = String::from_utf8(
        std::fs::read("src/asymmetric_crypto/rsa/tests/openssl/rsa_3072_bit.key.pkcs8.pem")
            .unwrap(),
    )
    .unwrap();
    // load the RSA private key from the PEM file
    let rsa_private_key = RsaPrivateKey::from_pkcs8_pem(&rsa_private_key_pem).unwrap();

    // use the wrapped_secret generated by openssl using the crate

    let recovered = rsa_private_key
        .unwrap_key(RsaKeyWrappingAlgorithm::OaepSha256, wrapped_secret)
        .unwrap();

    assert_eq!(recovered, secret);

    // use the ile generated by openssl using the CLI
    let wrapped_secret = Zeroizing::from(
        std::fs::read("src/asymmetric_crypto/rsa/tests/openssl/32_byte.key.oaep_sha256.enc")
            .unwrap(),
    );

    let recovered = rsa_private_key
        .unwrap_key(RsaKeyWrappingAlgorithm::OaepSha256, &wrapped_secret)
        .unwrap();

    assert_eq!(recovered, secret);
}
