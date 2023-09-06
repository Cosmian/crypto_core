use crypto_box::{PublicKey, SecretKey};

use crate::{
    asymmetric_crypto::{X25519PrivateKey, X25519PublicKey},
    reexport::rand_core::CryptoRngCore,
    Ecies,
};

/// The `EciesSalsaSealBox` struct provides Elliptic Curve Integrated Encryption
/// Scheme (ECIES) functionality.
///
/// This implementation is compatible with `libsodium` sealed box: `<https://doc.libsodium.org/public-key_cryptography/sealed_boxe>`
///
/// __Algorithm details__
///
/// Sealed boxes leverage the `crypto_box` construction, which uses X25519 and
/// XSalsa20-Poly1305.
///
/// The format of a sealed box is:
///
/// `ephemeral_pk ‖ box(m, recipient_pk, ephemeral_sk,
/// nonce=blake2b(ephemeral_pk ‖ recipient_pk))`
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use rand_chacha::rand_core::SeedableRng;
/// use cosmian_crypto_core::{
///     Ecies, EciesSalsaSealBox, X25519PrivateKey, X25519PublicKey,
///    CsRng, RandomFixedSizeCBytes
/// };
///
/// // Instantiate a cryptographic random number generator
/// let mut rng = CsRng::from_entropy();
///
/// // Generate a key pair
/// let private_key =
///     X25519PrivateKey::new(&mut rng);
/// let public_key = X25519PublicKey::from(&private_key);
///
/// // The plaintext message to be encrypted
/// let plaintext = b"Hello World!";
///
/// // Encrypt the plaintext message with the public key
/// let ciphertext =
///            EciesSalsaSealBox::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
///
/// // Verify that the size of the ciphertext is as expected
/// assert_eq!(ciphertext.len(), plaintext.len() + EciesSalsaSealBox::ENCRYPTION_OVERHEAD);
///
/// // Decrypt the ciphertext back into plaintext with the private key
/// let plaintext_ = EciesSalsaSealBox::decrypt(&private_key, &ciphertext, None).unwrap();
///
/// // Check that the decrypted text matches the original plaintext
/// assert_eq!(plaintext, &plaintext_[..]);
/// ```
///
/// The `new_from_rng` function allows the use of a custom random number
/// generator.
pub struct EciesSalsaSealBox {}

impl Ecies<X25519PrivateKey, X25519PublicKey> for EciesSalsaSealBox {
    const ENCRYPTION_OVERHEAD: usize = crypto_box::SEALBYTES;

    /// Encrypts a message using the given public key
    /// using a Salsa sealed box which is compatible with the
    /// libsodium sealed box: `<https://doc.libsodium.org/public-key_cryptography/sealed_boxe>`
    ///
    /// Note: the authentication data is not used by this algorithm and is
    /// ignored
    fn encrypt<R: CryptoRngCore>(
        rng: &mut R,
        public_key: &X25519PublicKey,
        plaintext: &[u8],
        _authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, crate::CryptoCoreError> {
        let public_key: PublicKey = public_key.0.into();
        public_key
            .seal(&mut *rng, plaintext)
            .map_err(|_| crate::CryptoCoreError::EncryptionError)
    }

    /// Decrypts a message using the given private key
    /// using a Salsa sealed box which is compatible with the
    /// libsodium sealed box: `<https://doc.libsodium.org/public-key_cryptography/sealed_boxe>`
    ///
    /// Note: the authentication data is not used by this algorithm and is
    /// ignored
    fn decrypt(
        private_key: &X25519PrivateKey,
        ciphertext: &[u8],
        _authentication_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, crate::CryptoCoreError> {
        let secret_key: SecretKey = private_key.0.into();
        secret_key
            .unseal(ciphertext)
            .map_err(|_| crate::CryptoCoreError::DecryptionError)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        asymmetric_crypto::{X25519PrivateKey, X25519PublicKey},
        ecies::ecies_salsa_sealed_box::EciesSalsaSealBox,
        CryptoCoreError, CsRng, Ecies, Ed25519PrivateKey, Ed25519PublicKey, FixedSizeCBytes,
        RandomFixedSizeCBytes,
    };
    use openssl::{
        asn1::{Asn1Integer, Asn1Time},
        bn::BigNum,
        ec::{EcGroup, EcKey},
        error::ErrorStack,
        nid::Nid,
        pkcs12::Pkcs12,
        pkey::{PKey, Public},
        x509::X509Builder,
    };
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn ecies_salsa_seal_box() {
        let mut rng = CsRng::from_entropy();
        // generate a secret key
        let private_key = X25519PrivateKey::new(&mut rng);
        let public_key = X25519PublicKey::from(&private_key);
        // encrypt
        let plaintext = b"Hello World!";
        let ciphertext =
            EciesSalsaSealBox::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
        // check the size is the expected size
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + EciesSalsaSealBox::ENCRYPTION_OVERHEAD
        );
        // decrypt
        let plaintext_ = EciesSalsaSealBox::decrypt(&private_key, &ciphertext, None).unwrap();
        // assert
        assert_eq!(plaintext, &plaintext_[..]);
    }

    #[test]
    fn libsodium_compat() {
        let mut rng = CsRng::from_entropy();

        let message = b"Hello World!";
        let mut ciphertext: Vec<u8> =
            vec![0; libsodium_sys::crypto_box_SEALBYTES as usize + message.len()];

        let mut public_key_bytes = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];
        let mut private_key_bytes = [0u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize];

        // encrypt using libsodium
        unsafe {
            // initialize the public and private key
            let public_key_ptr: *mut libc::c_uchar = public_key_bytes.as_mut_ptr().cast::<u8>();
            let private_key_ptr: *mut libc::c_uchar = private_key_bytes.as_mut_ptr().cast::<u8>();
            libsodium_sys::crypto_box_keypair(public_key_ptr, private_key_ptr);

            // encrypt using libsodium
            let message_ptr: *const libc::c_uchar = message.as_ptr().cast::<u8>();
            let ciphertext_ptr: *mut libc::c_uchar = ciphertext.as_mut_ptr().cast::<u8>();
            libsodium_sys::crypto_box_seal(
                ciphertext_ptr,
                message_ptr,
                message.len() as u64,
                public_key_ptr,
            );
        }

        // decrypt using salsa_sealbox
        let private_key = X25519PrivateKey::try_from_bytes(private_key_bytes).unwrap();
        // decrypt
        let message_ = EciesSalsaSealBox::decrypt(&private_key, &ciphertext, None).unwrap();
        // assert
        assert_eq!(message, &message_[..]);

        // the other way round:
        //
        // encrypt using salsa_sealbox
        let public_key = X25519PublicKey::from(&private_key);
        let ciphertext = EciesSalsaSealBox::encrypt(&mut rng, &public_key, message, None).unwrap();

        //decrypt using libsodium
        let mut plaintext_: Vec<u8> = vec![0; message.len()];
        unsafe {
            let plaintext_ptr: *mut libc::c_uchar = plaintext_.as_mut_ptr().cast::<u8>();
            let ciphertext_ptr: *const libc::c_uchar = ciphertext.as_ptr().cast::<u8>();
            let private_key_ptr: *const libc::c_uchar = private_key_bytes.as_ptr().cast::<u8>();
            let public_key_ptr: *const libc::c_uchar = public_key_bytes.as_ptr().cast::<u8>();

            libsodium_sys::crypto_box_seal_open(
                plaintext_ptr,
                ciphertext_ptr,
                ciphertext.len() as u64,
                public_key_ptr,
                private_key_ptr,
            );
        }

        assert_eq!(plaintext_, message);
    }

    #[test]
    fn ecies_salsa_seal_box_edwards() {
        let mut rng = CsRng::from_entropy();
        let ed25519_sk = Ed25519PrivateKey::new(&mut rng);
        let ed25519_pk = Ed25519PublicKey::from(&ed25519_sk);
        let ed25519_sk_bytes = ed25519_sk.to_bytes();

        // convert the ED25519 private key to an X25519 PrivateKey
        let x25519_sk = X25519PrivateKey::from_ed25519_private_key(&ed25519_sk);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        let mut rng = CsRng::from_entropy();
        // generate a secret key
        let private_key = X25519PrivateKey::new(&mut rng);
        let public_key = X25519PublicKey::from(&private_key);
        // encrypt
        let plaintext = b"Hello World!";
        let ciphertext =
            EciesSalsaSealBox::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
        // check the size is the expected size
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + EciesSalsaSealBox::ENCRYPTION_OVERHEAD
        );
        // decrypt
        let plaintext_ = EciesSalsaSealBox::decrypt(&private_key, &ciphertext, None).unwrap();
        // assert
        assert_eq!(plaintext, &plaintext_[..]);
    }

    fn test_openssl_dalek() {
        let p12 = generate_self_signed_cert("common_name", "", Nid::Ed25519).unwrap();

        // Step 1: Generate a new EC key pair with curve 25519
        let group = EcGroup::from_curve_name(Nid::X25519)?;
        let eckey = EcKey::generate(&group)?;

        // Step 2: Create a new X509 certificate and set the public key
        let pkey = PKey::from_ec_key(eckey)?;
    }

    pub(crate) fn generate_self_signed_cert(
        common_name: &str,
        pkcs12_password: &str,
        curve_nid: Nid,
    ) -> Result<Pkcs12, CryptoCoreError> {
        let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
        let group = EcGroup::from_curve_name(curve_nid)?;
        let ec_key = EcKey::generate(&group)?;
        let public_ec_key = ec_key.public_key_to_der()?;

        // We need to convert these keys to PKey objects to use in certificates
        let private_key = PKey::from_ec_key(ec_key)?;
        let public_key = PKey::<Public>::public_key_from_der(&public_ec_key)?;

        // Create a new X509 builder.
        let mut builder = X509Builder::new()?;

        // Assign the public key
        builder.set_pubkey(&public_key)?;

        // Set the common name and the rest of the subject of the certificate.
        let mut x509_name = openssl::x509::X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", "FR")?;
        x509_name.append_entry_by_text("ST", "IdF")?;
        x509_name.append_entry_by_text("O", "Cosmian KMS")?;
        x509_name.append_entry_by_text("CN", common_name)?;
        let x509_name = x509_name.build();
        builder.set_subject_name(&x509_name)?;

        // Set the issuer name (the same as the subject name since this is a self-signed certificate).
        builder.set_issuer_name(&x509_name)?;

        // Set the certificate serial number to some value.
        builder
            .set_serial_number(Asn1Integer::from_bn(BigNum::from_u32(12345)?.as_ref())?.as_ref())?;

        // Set the certificate validity period to 1 day.
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;

        // Set the key usage extension to allow the certificate to be used for TLS.
        builder.append_extension(
            openssl::x509::extension::KeyUsage::new()
                .key_encipherment()
                .digital_signature()
                .build()?,
        )?;

        builder.sign(&private_key, openssl::hash::MessageDigest::sha256())?;
        // now build the certificate
        let cert = builder.build();

        let pem = cert.to_pem()?;
        // write the pem to a cert.pem file in /tmp
        std::fs::write("/tmp/cert.pem", pem)?;

        // wrap it in a PKCS12 container
        let pkcs12 = Pkcs12::builder()
            .name(common_name)
            .pkey(&private_key)
            .cert(&cert)
            .build2(pkcs12_password)?;
        Ok(pkcs12)
    }

    impl From<std::io::Error> for crate::CryptoCoreError {
        fn from(_: std::io::Error) -> Self {
            crate::CryptoCoreError::EncryptionError
        }
    }

    impl From<ErrorStack> for crate::CryptoCoreError {
        fn from(_: ErrorStack) -> Self {
            crate::CryptoCoreError::EncryptionError
        }
    }
}
