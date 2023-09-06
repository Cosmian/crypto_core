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
        asymmetric_crypto::{Ed25519PrivateKey, X25519PrivateKey, X25519PublicKey},
        ecies::ecies_salsa_sealed_box::EciesSalsaSealBox,
        CsRng, Ecies, Ed25519PublicKey, FixedSizeCBytes, RandomFixedSizeCBytes,
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
    fn ecies_salsa_seal_box_ed() {
        let mut rng = CsRng::from_entropy();
        // Generate an ED25519 key pair
        let ed25519_sk = Ed25519PrivateKey::new(&mut rng);
        let ed25519_pk = Ed25519PublicKey::from(&ed25519_sk);

        // generate an X25519 public key from the ED25519 public key
        let x25519_pk = X25519PublicKey::from_ed25519_public_key(&ed25519_pk);
        // encrypt
        let plaintext = b"Hello World!";
        let ciphertext = EciesSalsaSealBox::encrypt(&mut rng, &x25519_pk, plaintext, None).unwrap();
        // check the size is the expected size
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + EciesSalsaSealBox::ENCRYPTION_OVERHEAD
        );

        // generate the corresponding X25519 private key from the ED25519 private key
        let x25519_sk = X25519PrivateKey::from_ed25519_private_key(&ed25519_sk);

        // decrypt
        let plaintext_ = EciesSalsaSealBox::decrypt(&x25519_sk, &ciphertext, None).unwrap();
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
}
