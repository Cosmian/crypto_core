mod private_key;
pub use private_key::RsaPrivateKey;

mod public_key;
pub use public_key::RsaPublicKey;

#[cfg(feature = "ser")]
use crate::CryptoCoreError;

/// Supported RSA key length (length of the modulus)
///
/// To be compliant with FIPS 186-5 (Digital Signature standards),
/// the length of the modulus must be greater than 2048 bits.
/// [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf]
pub enum KeyLength {
    Modulus2048 = 2048,
    Modulus3072 = 3072,
    Modulus4096 = 4096,
}

/// Supported PKCS#11 compatible key wrapping algorithms for RSA
///
/// Check the PKCS#11 OASIS specification for more details
/// [https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html]
pub enum KeyWrappingAlgorithm {
    /// PKCS #1 v1.5 RS following PKCS#11 CKM_RSA_PKCS
    /// The maximum possible plaintext length is m = k - 11,
    /// where k is the size of the RSA modulus.
    Pkcs1v1_5,
    /// PKCS #1 RSA with OAEP block format following PKCS#11 CKM_RSA_PKCS_OAEP
    /// The maximum possible plaintext length is m = k - 2 * h_len - 2,
    /// where k is the size of the RSA modulus
    /// and h_len is the size of the hash of the optional label.
    Oaep,
    /// Key wrap with AES following PKCS#11 CKM_RSA_AES_KEY_WRAP
    /// using an AES key of 128 bits.
    /// This is the recommended, non post-quantum, key wrapping algorithm
    /// since there is no limitation on the size of the plaintext; the recommended
    /// plaintext format for an EC Private key is PKCS#8
    Aes128KeyWrap,
    /// Key wrap with AES following PKCS#11 CKM_RSA_AES_KEY_WRAP
    /// using an AES key of 256 bits.
    /// For larger RSA modulus sizes, this is the recommended key wrapping algorithm
    /// since there is no limitation on the size of the plaintext; the recommended
    /// plaintext format for an EC Private key is PKCS#8
    Aes256KeyWrap,
}

impl From<rsa::errors::Error> for CryptoCoreError {
    fn from(e: rsa::errors::Error) -> Self {
        CryptoCoreError::RsaError(e.to_string())
    }
}
