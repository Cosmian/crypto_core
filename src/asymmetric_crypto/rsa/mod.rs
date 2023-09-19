mod private_key;
pub use private_key::RsaPrivateKey;

mod public_key;
pub use public_key::RsaPublicKey;

#[cfg(test)]
mod tests;

/// Supported RSA key length (length of the modulus)
///
/// To be compliant with FIPS 186-5 (Digital Signature standards),
/// the length of the modulus must be greater than 2048 bits.
/// [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RsaKeyLength {
    Modulus2048 = 2048,
    Modulus3072 = 3072,
    Modulus4096 = 4096,
}

/// Supported PKCS#11 compatible key wrapping algorithms for RSA
///
/// If in doubt, use the `Aes256Sha256` algorithm with a 3072 bits RSA key.
///
/// Check the PKCS#11 OASIS specification for more details
/// [https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html]
///
/// For Google Cloud KMS compatibility, check:
/// [https://cloud.google.com/kms/docs/key-wrapping?hl=en]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyWrappingAlgorithm {
    /// PKCS #1 v1.5 RS following PKCS#11 CKM_RSA_PKCS
    /// The maximum possible plaintext length is m = k - 11,
    /// where k is the size of the RSA modulus.
    Pkcs1v1_5,
    /// PKCS #1 RSA with OAEP block format following PKCS#11 CKM_RSA_PKCS_OAEP
    /// The hash function used is SHA256
    /// The maximum possible plaintext length is m = k - 2 * h_len - 2,
    /// where k is the size of the RSA modulus
    /// and h_len is the size of the hash of the optional label.
    OaepSha256,
    /// PKCS #1 RSA with OAEP block format following PKCS#11 CKM_RSA_PKCS_OAEP
    /// The hash function used is SHA1. For that reason this algorithm is not
    /// recommended and is only kept here for compatibility with legacy
    /// systems. The maximum possible plaintext length is m = k - 2 * h_len
    /// - 2, where k is the size of the RSA modulus
    /// and h_len is the size of the hash of the optional label.
    /// This algorithm is compatible with Google Cloud KMS
    ///  - RSA_OAEP_3072_SHA256 with RSA 3072 bits key
    ///  - RSA_OAEP_4096_SHA256 with RSA 4096 bits key
    OaepSha1,
    /// PKCS #1 RSA with OAEP block format following PKCS#11 CKM_RSA_PKCS_OAEP
    /// The hash function used is SHA3.
    /// and is only kept here for compatibility with legacy systems.
    /// The maximum possible plaintext length is m = k - 2 * h_len - 2,
    /// where k is the size of the RSA modulus
    /// and h_len is the size of the hash of the optional label.
    OaepSha3,
    /// Key wrap with AES following PKCS#11 CKM_RSA_AES_KEY_WRAP
    /// using an AES key of 256 bits. The hash function used is SHA256.
    /// The AES wrapping follows the RFC 5649 which is compatible with PKCS#11
    /// CKM_AES_KEY_WRAP_KWP since there is no limitation on the size of the
    /// plaintext; the recommended plaintext format for an EC Private key is
    /// PKCS#8. This is the recommended key wrapping algorithm.
    /// This algorithm is compatible with Google Cloud KMS
    ///  - RSA_OAEP_3072_SHA256_AES_256 for RSA 3072 bits key
    ///  - RSA_OAEP_4096_SHA256_AES_256 for RSA 4096 bits key
    Aes256Sha256,
    /// Key wrap with AES following PKCS#11 CKM_RSA_AES_KEY_WRAP
    /// using an AES key of 256 bits. The hash function used is SHA1.
    /// For that reason this algorithm is not recommended
    /// and is only kept here for compatibility with legacy systems.
    /// The AES wrapping follows the RFC 5649 which is compatible with PKCS#11
    /// CKM_AES_KEY_WRAP_KWP since there is no limitation on the size of the
    /// plaintext; the recommended plaintext format for an EC Private key is
    /// PKCS#8. This algorithm is compatible with Google Cloud KMS
    ///  - RSA_OAEP_3072_SHA1_AES_256 for RSA 3072 bits key
    ///  - RSA_OAEP_4096_SHA1_AES_256 for RSA 4096 bits key
    Aes256Sha1,
    /// Key wrap with AES following PKCS#11 CKM_RSA_AES_KEY_WRAP
    /// using an AES key of 256 bits. The hash function used is SHA3-256
    /// (defined in FIPS 202). The AES wrapping follows the RFC 5649 which
    /// is compatible with PKCS#11 CKM_AES_KEY_WRAP_KWP since there is no
    /// limitation on the size of the plaintext; the recommended
    /// plaintext format for an EC Private key is PKCS#8.
    Aes256Sha3,
}
