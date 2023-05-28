use std::{
    ops::{Add, Div, Mul, Sub},
    sync::{Arc, Mutex},
};

use rand_chacha::rand_core::SeedableRng;

use crate::{
    asymmetric_crypto::{ecies::Ecies, DhKeyPair},
    kdf,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{
        aes_256_gcm_pure::{
            decrypt_combined, encrypt_combined, Aes256GcmCrypto, KEY_LENGTH as SYMMETRIC_KEY_LENGTH,
        },
        nonce::NonceTrait,
        Dem,
    },
    CryptoCoreError, CsRng, KeyTrait,
};

use super::{
    R25519KeyPair, R25519PrivateKey, R25519PublicKey, R25519_PRIVATE_KEY_LENGTH,
    R25519_PUBLIC_KEY_LENGTH,
};

/// A thread safe Elliptic Curve Integrated Encryption Scheme (ECIES) using
///  - the Ristretto group of Curve 25516
///  - AES 256 GCM
///  - SHAKE256 (XOF)
pub struct EciesR25519Aes256gcmSha256Xof {
    cs_rng: Arc<Mutex<CsRng>>,
}

impl EciesR25519Aes256gcmSha256Xof {
    /// Creates a new instance of `EciesR25519Aes256gcmSha256Xof`.
    #[must_use]
    pub fn new() -> Self {
        Self::new_from_rng(Arc::new(Mutex::new(CsRng::from_entropy())))
    }

    /// Creates a new instance of `EciesR25519Aes256gcmSha256Xof`
    /// from an existing cryptographic pseudo random generator
    #[must_use]
    pub fn new_from_rng(cs_rng: Arc<Mutex<CsRng>>) -> Self {
        Self { cs_rng }
    }
}

impl Ecies<R25519_PUBLIC_KEY_LENGTH, R25519_PRIVATE_KEY_LENGTH> for EciesR25519Aes256gcmSha256Xof {
    type PrivateKey = R25519PrivateKey;

    type PublicKey = R25519PublicKey;

    const ENCRYPTION_OVERHEAD: usize =
        R25519_PUBLIC_KEY_LENGTH + Aes256GcmCrypto::ENCRYPTION_OVERHEAD;

    fn encrypt(
        &self,
        public_key: &Self::PublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoCoreError> {
        let mut rng = self.cs_rng.lock().expect("failed to lock cs_rng");
        ecies_encrypt::<
            CsRng,
            R25519KeyPair,
            { R25519KeyPair::PUBLIC_KEY_LENGTH },
            { R25519KeyPair::PRIVATE_KEY_LENGTH },
        >(&mut rng, &public_key, plaintext, None, None)
    }

    fn decrypt(
        &self,
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoCoreError> {
        ecies_decrypt::<
            R25519KeyPair,
            { R25519KeyPair::PUBLIC_KEY_LENGTH },
            { R25519KeyPair::PRIVATE_KEY_LENGTH },
        >(private_key, &ciphertext, None, None)
    }
}

/// Encrypts a message using Elliptic Curve Integrated Encryption Scheme
/// (ECIES). This implementation uses SHAKE256 (XOF) as a KDF and AES256-GCM as
/// a symmetric cipher.
///
/// This function encrypts a given message using ECIES with the provided
/// receiver's public key.
///
/// # Arguments
///
/// * `rng`: A mutable reference to a cryptographically secure random number
///   generator.
/// * `receiver_public_key`: A reference to the receiver's public key.
/// * `msg`: A byte slice representing the message to be encrypted.
/// * `shared_encapsulation_data`: An optional byte slice of data used in the
///   symmetric key computation
/// * `shared_authentication_data`: An optional byte slice of data used in the
///   DEM encryption.
///
/// # Returns
///
/// * The encrypted message as a `Vec<u8>`, or a `CryptoCoreError` if an error
///   occurs.
///
/// # Example
///
/// ```
/// use cosmian_crypto_core::{
///    asymmetric_crypto::{
///         DhKeyPair,
///         R25519KeyPair, ecies_encrypt,
///     },
///    reexport::rand_core::SeedableRng,
///    CsRng,
/// };
///
/// let mut rng = CsRng::from_entropy();
/// let key_pair = R25519KeyPair::new(&mut rng);
/// let msg = b"Hello, World!";
///
/// let _encrypted_message = ecies_encrypt::<
///         CsRng,
///         R25519KeyPair,
///         { R25519KeyPair::PUBLIC_KEY_LENGTH },
///         { R25519KeyPair::PRIVATE_KEY_LENGTH },
///     >(
///     &mut rng,
///     &key_pair.public_key(),
///     msg,
///     None,
///     None
/// ).unwrap();
/// ```
pub fn ecies_encrypt<R, DH, const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize>(
    rng: &mut R,
    receiver_public_key: &DH::PublicKey,
    msg: &[u8],
    shared_encapsulation_data: Option<&[u8]>,
    shared_authentication_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError>
where
    R: CryptoRngCore,
    DH: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    DH::PublicKey: From<DH::PrivateKey>,
    for<'a, 'b> &'a DH::PublicKey: Add<&'b DH::PublicKey, Output = DH::PublicKey>
        + Mul<&'b DH::PrivateKey, Output = DH::PublicKey>,
    for<'a, 'b> &'a DH::PrivateKey: Add<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Sub<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Mul<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Div<&'b DH::PrivateKey, Output = DH::PrivateKey>,
{
    // Generate an ephemeral key pair (r, R) where R = r.G
    let ephemeral_key_pair = DH::new(rng);

    // Calculate the shared secret point (Px, Py) = P = r.Y
    let shared_point = receiver_public_key * ephemeral_key_pair.private_key();

    // Generate the 256-bit symmetric encryption key k, derived using SHAKE256 eXtendable-Output-Function (XOF)
    // such as: k = kdf(S || S1) where:
    // * S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
    // * S1: if the user provided shared_encapsulation_data S1, then we append it to
    //   the shared_bytes S
    let key = if let Some(s1) = shared_encapsulation_data {
        kdf!(SYMMETRIC_KEY_LENGTH, &shared_point.to_bytes(), s1)
    } else {
        kdf!(SYMMETRIC_KEY_LENGTH, &shared_point.to_bytes())
    };

    // Encrypt the message using AES-256-GCM
    let nonce = <Aes256GcmCrypto as Dem<SYMMETRIC_KEY_LENGTH>>::Nonce::new(rng);

    // Encrypt and authenticate the message, returning the ciphertext and MAC
    let ciphertext_plus_tag =
        encrypt_combined(&key, msg, nonce.as_bytes(), shared_authentication_data)?;

    // Assemble the final encrypted message: R || nonce || c || d
    let mut res =
        Vec::with_capacity(PUBLIC_KEY_LENGTH + Aes256GcmCrypto::ENCRYPTION_OVERHEAD + msg.len());
    res.extend(ephemeral_key_pair.public_key().to_bytes().to_vec());
    res.extend(nonce.as_bytes());
    res.extend(&ciphertext_plus_tag);

    Ok(res)
}

/// Decrypts a message using Elliptic Curve Integrated Encryption Scheme
/// (ECIES). This implementation uses SHAKE256 (XOF) as a KDF and AES256-GCM as
/// a symmetric cipher.
///
/// This function decrypts a given message using ECIES with the provided
/// receiver's private key. The decrypted message is returned as a
/// `Result<Vec<u8>, CryptoCoreError>`.
///
/// # Arguments
///
/// * `receiver_private_key`: A reference to the receiver's private key.
/// * `ciphertext`: A byte slice representing the ciphertext to be decrypted.
/// * `shared_encapsulation_data`: An optional byte slice of data used in the
///   symmetric key computation
/// * `shared_authentication_data`: An optional byte slice of data used in the
///   DEM decryption.
///
/// # Returns
///
/// * The decrypted message as a `Vec<u8>`, or a `CryptoCoreError` if an error
///   occurs.
///
/// # Example
///
/// ```
/// use cosmian_crypto_core::{
///     asymmetric_crypto::{
///         DhKeyPair,
///         R25519KeyPair,ecies_encrypt, ecies_decrypt
///     },
///     reexport::rand_core::SeedableRng,
///     CsRng,
/// };
///
/// let mut rng = CsRng::from_entropy();
/// let key_pair = R25519KeyPair::new(&mut rng);
/// let msg = b"Hello, World!";
///
/// // Encrypt the message
/// let encrypted_message = ecies_encrypt::<
///     CsRng,
///     R25519KeyPair,
///     { R25519KeyPair::PUBLIC_KEY_LENGTH },
///     { R25519KeyPair::PRIVATE_KEY_LENGTH },
/// >(
///     &mut rng,
///     &key_pair.public_key(),
///     msg,
///     None,
///     None
/// ).unwrap();
///
/// // Decrypt the encrypted message
/// let decrypted_message = ecies_decrypt::<
///     R25519KeyPair,
///     { R25519KeyPair::PUBLIC_KEY_LENGTH },
///     { R25519KeyPair::PRIVATE_KEY_LENGTH },
/// >(
///     &key_pair.private_key(),
///     &encrypted_message,
///     None,
///     None
/// ).unwrap();
///
/// // Check if the decrypted message is the same as the original message
/// assert_eq!(msg, &decrypted_message[..]);
/// ```
pub fn ecies_decrypt<DH, const PUBLIC_KEY_LENGTH: usize, const PRIVATE_KEY_LENGTH: usize>(
    receiver_private_key: &DH::PrivateKey,
    ciphertext: &[u8],
    shared_encapsulation_data: Option<&[u8]>,
    shared_authentication_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoCoreError>
where
    DH: DhKeyPair<PUBLIC_KEY_LENGTH, PRIVATE_KEY_LENGTH>,
    DH::PublicKey: From<DH::PrivateKey>,
    for<'a, 'b> &'a DH::PublicKey: Add<&'b DH::PublicKey, Output = DH::PublicKey>
        + Mul<&'b DH::PrivateKey, Output = DH::PublicKey>,
    for<'a, 'b> &'a DH::PrivateKey: Add<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Sub<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Mul<&'b DH::PrivateKey, Output = DH::PrivateKey>
        + Div<&'b DH::PrivateKey, Output = DH::PrivateKey>,
{
    // Extract the sender's ephemeral public key R from the ciphertext
    let ephemeral_public_key = &ciphertext[..PUBLIC_KEY_LENGTH];
    let sender_public_key = DH::PublicKey::try_from_bytes(ephemeral_public_key)?;

    // Calculate the shared secret point (Px, Py) = P = R.y = r.G.y = r.Y
    let shared_point = &sender_public_key * receiver_private_key;

    // Generate the 256-bit symmetric encryption key k, derived using SHAKE256 XOF
    // such as: k = kdf(S || S1) where:
    // * S = Px. Note: ECIES formally uses S = Px rather than the serialization of P
    // * S1: if the user provided shared_encapsulation_data S1, then we append it to
    //   the shared_bytes S
    let key = if let Some(s1) = shared_encapsulation_data {
        kdf!(SYMMETRIC_KEY_LENGTH, &shared_point.to_bytes(), s1)
    } else {
        kdf!(SYMMETRIC_KEY_LENGTH, &shared_point.to_bytes())
    };

    // Extract the nonce from the ciphertext
    let nonce_start = PUBLIC_KEY_LENGTH;
    let nonce_end = nonce_start + <Aes256GcmCrypto as Dem<SYMMETRIC_KEY_LENGTH>>::Nonce::LENGTH;
    let nonce = &ciphertext[nonce_start..nonce_end];

    // Separate the encrypted message and MAC from the ciphertext
    let ciphertext_plus_tag = &ciphertext[nonce_end..];

    // Decrypt and verify the message using AES-256-GCM
    let decrypted_message =
        decrypt_combined(&key, ciphertext_plus_tag, nonce, shared_authentication_data)?;

    Ok(decrypted_message)
}

#[cfg(test)]
mod tests {
    use super::{ecies_decrypt, ecies_encrypt, CryptoCoreError};
    use crate::{
        asymmetric_crypto::{DhKeyPair, R25519KeyPair},
        reexport::rand_core::SeedableRng,
        CsRng,
    };

    #[test]
    fn test_encrypt_decrypt() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let key_pair: R25519KeyPair = R25519KeyPair::new(&mut rng);
        let msg = b"Hello, World!";

        // Encrypt the message
        let encrypted_message = ecies_encrypt::<
            CsRng,
            R25519KeyPair,
            { R25519KeyPair::PUBLIC_KEY_LENGTH },
            { R25519KeyPair::PRIVATE_KEY_LENGTH },
        >(&mut rng, key_pair.public_key(), msg, None, None)?;

        // Decrypt the message
        let decrypted_message = ecies_decrypt::<
            R25519KeyPair,
            { R25519KeyPair::PUBLIC_KEY_LENGTH },
            { R25519KeyPair::PRIVATE_KEY_LENGTH },
        >(key_pair.private_key(), &encrypted_message, None, None)?;

        // Check if the decrypted message is the same as the original message
        assert_eq!(msg, &decrypted_message[..]);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_with_optional_data() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let key_pair: R25519KeyPair = R25519KeyPair::new(&mut rng);
        let msg = b"Hello, World!";
        let encapsulated_data = b"Optional Encapsulated Data";
        let authentication_data = b"Optional Authentication Data";

        // Encrypt the message with encapsulated_data and authentication_data
        let encrypted_message = ecies_encrypt::<
            CsRng,
            R25519KeyPair,
            { R25519KeyPair::PUBLIC_KEY_LENGTH },
            { R25519KeyPair::PRIVATE_KEY_LENGTH },
        >(
            &mut rng,
            key_pair.public_key(),
            msg,
            Some(encapsulated_data),
            Some(authentication_data),
        )?;

        // Decrypt the message with encapsulated_data and authentication_data
        let decrypted_message = ecies_decrypt::<
            R25519KeyPair,
            { R25519KeyPair::PUBLIC_KEY_LENGTH },
            { R25519KeyPair::PRIVATE_KEY_LENGTH },
        >(
            key_pair.private_key(),
            &encrypted_message,
            Some(encapsulated_data),
            Some(authentication_data),
        )?;

        // Check if the decrypted message is the same as the original message
        assert_eq!(msg, &decrypted_message[..]);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_with_optional_data_but_corrupted() -> Result<(), CryptoCoreError> {
        let mut rng = CsRng::from_entropy();
        let key_pair: R25519KeyPair = R25519KeyPair::new(&mut rng);
        let msg = b"Hello, World!";
        let encapsulated_data = b"Optional Encapsulated Data";
        let authentication_data = b"Optional Authentication Data";

        // Encrypt the message with encapsulated_data and authentication_data
        let encrypted_message = ecies_encrypt::<
            CsRng,
            R25519KeyPair,
            { R25519KeyPair::PUBLIC_KEY_LENGTH },
            { R25519KeyPair::PRIVATE_KEY_LENGTH },
        >(
            &mut rng,
            key_pair.public_key(),
            msg,
            Some(encapsulated_data),
            Some(authentication_data),
        )?;

        // Try to decrypt the message with encapsulated_data and authentication_data
        let not_decrypted = ecies_decrypt::<
            R25519KeyPair,
            { R25519KeyPair::PUBLIC_KEY_LENGTH },
            { R25519KeyPair::PRIVATE_KEY_LENGTH },
        >(
            key_pair.private_key(),
            &encrypted_message,
            Some(b"Other Optional Encapsulated Data"),
            Some(authentication_data),
        );
        assert!(matches!(
            not_decrypted,
            Err(CryptoCoreError::DecryptionError)
        ));

        // Try to decrypt the message with encapsulated_data and authentication_data
        let not_decrypted = ecies_decrypt::<
            R25519KeyPair,
            { R25519KeyPair::PUBLIC_KEY_LENGTH },
            { R25519KeyPair::PRIVATE_KEY_LENGTH },
        >(
            key_pair.private_key(),
            &encrypted_message,
            Some(encapsulated_data),
            Some(b"Other Optional Authentication Data"),
        );
        assert!(matches!(
            not_decrypted,
            Err(CryptoCoreError::DecryptionError)
        ));

        Ok(())
    }
}
