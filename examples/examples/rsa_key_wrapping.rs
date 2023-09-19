#[cfg(feature = "rsa")]
pub fn rsa_key_wrapping() {
    use cosmian_crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng, RsaKeyLength, RsaKeyWrappingAlgorithm, RsaPrivateKey,
    };
    use zeroize::Zeroizing;

    let mut rng = CsRng::from_entropy();
    println!("... Generating a 3072 bit RSA key ...");
    let rsa_private_key = RsaPrivateKey::new(&mut rng, RsaKeyLength::Modulus3072).unwrap();

    let mut key_to_wrap = [0_u8; 32];
    rng.fill_bytes(&mut key_to_wrap);

    let mut key_to_wrap = [0_u8; 189];
    rng.fill_bytes(&mut key_to_wrap);
    let key_to_wrap = Zeroizing::from(key_to_wrap.to_vec());

    let rsa_public_key = rsa_private_key.public_key();

    print!("Key wrapping with PKCS#11 CKM_RSA_AES_KEY_WRAP SHA-256 AES 256 ...");
    let wrapped_key = rsa_public_key
        .wrap_key(
            &mut rng,
            RsaKeyWrappingAlgorithm::Aes256Sha256,
            &key_to_wrap,
        )
        .unwrap();

    print!("unwrapping ...: ");
    let unwrapped_key = rsa_private_key
        .unwrap_key(RsaKeyWrappingAlgorithm::Aes256Sha256, &wrapped_key)
        .unwrap();

    assert_eq!(unwrapped_key, key_to_wrap);
    println!("OK");
}
