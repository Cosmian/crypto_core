use crate::reexport::rand_core::{CryptoRng, RngCore};

/// Create an [`SecretDocument`] containing the ciphertext of
/// a PKCS#8 encoded private key encrypted under the given `password`.
///
/// Due to in compatibility issues with the openssl library, we use the
/// modified parameters for Scrypt and cannot use the default implemented with
/// ```Rust
/// let bytes =
///     pkcs8::EncodePrivateKey::to_pkcs8_encrypted_der(&self.secret_key, &mut rng, password)
///         .map(|d| d.to_bytes())?;
/// ```
/// see this issue for more details and the PR progress that will fix it:
/// https://github.com/RustCrypto/formats/issues/1205
pub(crate) fn to_pkcs8_encrypted_der(
    secret_document: &pkcs8::SecretDocument,
    mut rng: impl CryptoRng + RngCore,
    password: impl AsRef<[u8]>,
) -> pkcs8::Result<pkcs8::SecretDocument> {
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);

    // 14 = log_2(16384), 32 bytes = 256 bits
    let scrypt_params = pkcs8::pkcs5::scrypt::Params::new(14, 8, 1, 32).unwrap();
    let pbes2_params =
        pkcs8::pkcs5::pbes2::Parameters::scrypt_aes256cbc(scrypt_params, &salt, &iv)?;

    let encrypted_data = pbes2_params.encrypt(password, secret_document.as_bytes())?;

    pkcs8::EncryptedPrivateKeyInfo {
        encryption_algorithm: pbes2_params.into(),
        encrypted_data: &encrypted_data,
    }
    .try_into()
}
