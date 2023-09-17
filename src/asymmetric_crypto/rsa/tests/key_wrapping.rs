use zeroize::Zeroizing;

use crate::reexport::rand_core::{RngCore, SeedableRng};

use crate::{CsRng, PrivateKey, RsaKeyLength, RsaKeyWrappingAlgorithm, RsaPrivateKey};

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

// #[test]
// fn test_openssl_compat() {
//     // load the RSA private key from the PEM file
//     let rsa_private_key = RsaPrivateKey::from_pem_file("tests/rsa_private_key.pem").unwrap();
// }
