use crate::{
    asymmetric_crypto::{X25519PrivateKey, X25519PublicKey},
    reexport::rand_core::CryptoRngCore,
    Ecies,
};
use crypto_box::{PublicKey, SecretKey};

/// The `EciesSalsaSealBox` struct provides Elliptic Curve Integrated Encryption Scheme (ECIES) functionality
/// utilizing Salsa20 as its encryption mechanism.
///
/// This implementation is compatible with `libsodium` sealed box: `<https://doc.libsodium.org/public-key_cryptography/sealed_boxe>`
///
/// This struct is used for public-key encryption and decryption where the `X25519PrivateKey` and `X25519PublicKey` types are used.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use rand_chacha::rand_core::SeedableRng;
/// use cosmian_crypto_core::{
///     asymmetric_crypto:: {
///         Ecies,
///         EciesSalsaSealBox, X25519PrivateKey, X25519PublicKey,
///     },
///    CsRng, KeyTrait,
///};
///
/// // Instantiate a cryptographic random number generator
/// let arc_rng = Arc::new(Mutex::new(CsRng::from_entropy()));
///
/// // Create a new instance of EciesSalsaSealBox
/// let ecies = EciesSalsaSealBox::new_from_rng(arc_rng.clone());
///
/// // Generate a secret key
/// let private_key = {
///     let mut rng = arc_rng.lock().unwrap();
///     X25519PrivateKey::new(&mut *rng)
/// };
/// let public_key = private_key.public_key();
///
/// // The plaintext message to be encrypted
/// let plaintext = b"Hello World!";
///
/// // Encrypt the plaintext message with the public key
/// let ciphertext = ecies.encrypt(&public_key, plaintext, None).unwrap();
///
/// // Verify that the size of the ciphertext is as expected
/// assert_eq!(ciphertext.len(), plaintext.len() + EciesSalsaSealBox::ENCRYPTION_OVERHEAD);
///
/// // Decrypt the ciphertext back into plaintext with the private key
/// let plaintext_ = ecies.decrypt(&private_key, &ciphertext, None).unwrap();
///
/// // Check that the decrypted text matches the original plaintext
/// assert_eq!(plaintext, &plaintext_[..]);
/// ```
///
/// The `new_from_rng` function allows the use of a custom random number generator.
pub struct EciesSalsaSealBox {}

impl Ecies<X25519PrivateKey, X25519PublicKey> for EciesSalsaSealBox {
    const ENCRYPTION_OVERHEAD: usize = crypto_box::SEALBYTES;

    /// Encrypts a message using the given public key
    /// using a Salsa sealed box which is compatible with the
    /// libsodium sealed box: `<https://doc.libsodium.org/public-key_cryptography/sealed_boxe>`
    ///
    /// Note: the authentication data is not used by this algorithm and is ignored
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
    /// Note: the authentication data is not used by this algorithm and is ignored
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

    use rand_chacha::rand_core::SeedableRng;

    use crate::{
        asymmetric_crypto::{X25519PrivateKey, X25519PublicKey},
        ecies::ecies_salsa_sealed_box::EciesSalsaSealBox,
        CsRng, Ecies, FixedSizeCBytes, RandomFixedSizeCBytes,
    };

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
            let public_key_ptr: *mut libc::c_uchar =
                public_key_bytes.as_mut_ptr() as *mut libc::c_uchar;
            let private_key_ptr: *mut libc::c_uchar =
                private_key_bytes.as_mut_ptr() as *mut libc::c_uchar;
            libsodium_sys::crypto_box_keypair(public_key_ptr, private_key_ptr);

            // encrypt using libsodium
            let message_ptr: *const libc::c_uchar = message.as_ptr() as *const libc::c_uchar;
            let ciphertext_ptr: *mut libc::c_uchar = ciphertext.as_mut_ptr() as *mut libc::c_uchar;
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
            let plaintext_ptr: *mut libc::c_uchar = plaintext_.as_mut_ptr() as *mut libc::c_uchar;
            let ciphertext_ptr: *const libc::c_uchar = ciphertext.as_ptr() as *const libc::c_uchar;
            let private_key_ptr: *const libc::c_uchar =
                private_key_bytes.as_ptr() as *const libc::c_uchar;
            let public_key_ptr: *const libc::c_uchar =
                public_key_bytes.as_ptr() as *const libc::c_uchar;

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
}
