use crate::{reexport::rand_core::SeedableRng, CsRng, RsaPrivateKey, RsaPublicKey};
use openssl::{
    pkey::{PKey, Public},
    rsa::Rsa,
    symm::Cipher,
};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};

use crate::CryptoCoreError;

#[test]
fn test_pkcs8_openssl_key_compat() -> Result<(), CryptoCoreError> {
    let private_key_rsa = Rsa::generate(3072)?;

    // convert to Openssl generic key
    let private_key = PKey::from_rsa(private_key_rsa)?;
    let private_key_pkcs8 = private_key.private_key_to_pkcs8()?;
    let public_key_pkcs8 = private_key.public_key_to_der()?;

    // convert to RSA private Key
    let rsa_public_key = RsaPublicKey::from_public_key_der(&public_key_pkcs8)?;
    let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&private_key_pkcs8)?;
    assert_eq!(rsa_private_key.public_key(), rsa_public_key);

    // convert back to openssl
    let openssl_private_key =
        PKey::private_key_from_pkcs8(&rsa_private_key.to_pkcs8_der().map(|d| d.to_bytes())?)?;
    // check same private key
    assert_eq!(
        openssl_private_key.private_key_to_der()?,
        private_key.private_key_to_der()?
    );
    let openssl_public_key =
        Rsa::public_key_from_der(&rsa_public_key.to_public_key_der().map(|d| d.to_vec())?)?;
    // check that the recovered public key matches the original one
    assert_eq!(
        private_key.public_key_to_pem()?,
        openssl_public_key.public_key_to_pem()?
    );

    Ok(())
}

#[test]
fn test_encrypted_pkcs8_openssl_key_compat() -> Result<(), CryptoCoreError> {
    let mut rng = CsRng::from_entropy();
    let private_key_rsa = Rsa::generate(3072)?;
    let private_key_pkcs1 = private_key_rsa.private_key_to_pem()?;

    // convert to Openssl generic key
    let private_key = PKey::from_rsa(private_key_rsa)?;
    let private_key_pkcs8 =
        private_key.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"blah")?;
    let public_key_pkcs8 = private_key.public_key_to_der()?;

    // convert to Nist private Key
    let rsa_public_key = RsaPublicKey::from_public_key_der(&public_key_pkcs8)?;
    let rsa_private_key = RsaPrivateKey::from_pkcs8_encrypted_der(&private_key_pkcs8, b"blah")?;
    assert_eq!(rsa_private_key.public_key(), rsa_public_key);

    // convert back to openssl
    let private_key_pkcs8 = rsa_private_key.to_pkcs8_encrypted_der(&mut rng, b"blah")?;
    {
        // check we can decrypt with this library
        let rsa_private_key_ =
            RsaPrivateKey::from_pkcs8_encrypted_der(private_key_pkcs8.as_bytes(), b"blah")?;
        assert_eq!(rsa_private_key_, rsa_private_key);
    }

    let openssl_private_key =
        PKey::private_key_from_pkcs8_passphrase(private_key_pkcs8.as_bytes(), b"blah")?;
    let openssl_rsa_key = openssl_private_key.rsa()?;
    // check same private key
    assert_eq!(openssl_rsa_key.private_key_to_pem()?, private_key_pkcs1);
    let openssl_public_key =
        PKey::<Public>::public_key_from_der(rsa_public_key.to_public_key_der()?.as_bytes())?;
    // check that the recovered public key matches the original one
    assert!(private_key.public_eq(&openssl_public_key));

    Ok(())
}
