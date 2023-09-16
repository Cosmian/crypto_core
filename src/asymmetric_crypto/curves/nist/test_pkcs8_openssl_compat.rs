#[cfg(test)]
mod tests {

    use openssl::{
        ec::{EcGroup, EcKey},
        error::ErrorStack,
        nid::Nid,
        pkey::{PKey, Public},
        symm::Cipher,
    };

    use crate::{CryptoCoreError, P256PrivateKey, P256PublicKey};

    #[test]
    fn test_pkcs8_openssl_key_compat() -> Result<(), CryptoCoreError> {
        let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
        let group = EcGroup::from_curve_name(nid)?;
        let ec_key = EcKey::generate(&group)?;
        // used or later assert
        let ec_ky_big_num = ec_key.private_key().to_owned()?;

        // convert to Openssl generic key
        let private_key = PKey::from_ec_key(ec_key)?;
        let private_key_pkcs8 = private_key.private_key_to_pkcs8()?;
        let public_key_pkcs8 = private_key.public_key_to_der()?;

        // convert to Nist private Key
        let nist_public_key = P256PublicKey::try_from_pkcs8(&public_key_pkcs8)?;
        let nist_private_key = P256PrivateKey::try_from_pkcs8(&private_key_pkcs8)?;
        assert_eq!(P256PublicKey::from(&nist_private_key), nist_public_key);

        // convert back to openssl
        let openssl_private_key = PKey::private_key_from_pkcs8(&nist_private_key.try_to_pkcs8()?)?;
        let openssl_ec_key = openssl_private_key.ec_key()?;
        // check same private key
        assert_eq!(openssl_ec_key.private_key().to_owned()?, ec_ky_big_num);
        let openssl_public_key =
            PKey::<Public>::public_key_from_der(&nist_public_key.try_to_pkcs8()?)?;
        // check that the recovered public key matches the original one
        assert!(private_key.public_eq(&openssl_public_key));

        Ok(())
    }

    #[test]
    fn test_encrypted_pkcs8_openssl_key_compat() -> Result<(), CryptoCoreError> {
        let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
        let group = EcGroup::from_curve_name(nid)?;
        let ec_key = EcKey::generate(&group)?;
        // used or later assert
        let ec_ky_big_num = ec_key.private_key().to_owned()?;

        // convert to Openssl generic key
        let private_key = PKey::from_ec_key(ec_key)?;
        let private_key_pkcs8 =
            private_key.private_key_to_pkcs8_passphrase(Cipher::aes_256_cbc(), b"blah")?;
        let public_key_pkcs8 = private_key.public_key_to_der()?;

        // convert to Nist private Key
        let nist_public_key = P256PublicKey::try_from_pkcs8(&public_key_pkcs8)?;
        let nist_private_key =
            P256PrivateKey::try_from_encrypted_pkcs8(&private_key_pkcs8, b"blah")?;
        assert_eq!(P256PublicKey::from(&nist_private_key), nist_public_key);

        // convert back to openssl
        let private_key_pkcs8 = nist_private_key.try_to_encrypted_pkcs8(b"blah")?;
        {
            // check we can decrypt with this library
            let nist_private_key_ =
                P256PrivateKey::try_from_encrypted_pkcs8(&private_key_pkcs8, b"blah")?;
            assert_eq!(nist_private_key_, nist_private_key);
        }

        let openssl_private_key =
            PKey::private_key_from_pkcs8_passphrase(private_key_pkcs8.as_ref(), b"blah")?;
        let openssl_ec_key = openssl_private_key.ec_key()?;
        // check same private key
        assert_eq!(openssl_ec_key.private_key().to_owned()?, ec_ky_big_num);
        let openssl_public_key =
            PKey::<Public>::public_key_from_der(&nist_public_key.try_to_pkcs8()?)?;
        // check that the recovered public key matches the original one
        assert!(private_key.public_eq(&openssl_public_key));

        Ok(())
    }

    impl From<std::io::Error> for crate::CryptoCoreError {
        fn from(_: std::io::Error) -> Self {
            Self::EncryptionError
        }
    }

    impl From<ErrorStack> for crate::CryptoCoreError {
        fn from(_: ErrorStack) -> Self {
            Self::EncryptionError
        }
    }
}
