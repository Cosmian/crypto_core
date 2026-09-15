use core::fmt::Display;

/// Error type for this crate.
#[derive(Debug)]
pub enum CryptoCoreError {
    Base(cosmian_crypto_base::Error),
    CiphertextTooSmallError {
        ciphertext_len: usize,
        min: u64,
    },
    CiphertextTooBigError {
        ciphertext_len: usize,
        max: u64,
    },
    ConversionError(String),
    DecryptionError,
    DeserializationEmptyError,
    DeserializationIoError {
        bytes_len: usize,
        error: String,
    },
    DeserializationSizeError {
        given: usize,
        expected: usize,
    },
    EllipticCurveError(String),
    EncryptionError,
    GenericDeserializationError(String),
    GenericSerializationError(String),
    InvalidBytesLength(String, usize, Option<usize>),
    PlaintextTooBigError {
        plaintext_len: usize,
        max: u64,
    },
    #[cfg(any(feature = "certificate", feature = "nist_curves"))]
    Certificate(String),
    #[cfg(any(feature = "certificate", feature = "nist_curves", feature = "rsa"))]
    Pkcs8Error(String),
    ReadLeb128Error(leb128::read::Error),
    #[cfg(feature = "rsa")]
    RsaError(String),
    SerializationIoError {
        bytes_len: usize,
        error: std::io::Error,
    },
    SignatureError(String),
    StreamCipherError(String),
    TryFromSliceError {
        expected: usize,
        given: usize,
    },
    WriteLeb128Error {
        value: u64,
        error: std::io::Error,
    },
    Shamir(String),
}

impl Display for CryptoCoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base(e) => write!(f, "crypto base error: {e}"),
            #[cfg(any(feature = "certificate", feature = "nist_curves"))]
            Self::Certificate(err) => write!(f, "when building certificate, {err}"),
            Self::CiphertextTooSmallError {
                ciphertext_len,
                min,
            } => write!(
                f,
                "when decrypting, ciphertext of {ciphertext_len} bytes is too small, min is {min} \
                 bytes"
            ),
            Self::CiphertextTooBigError {
                ciphertext_len,
                max,
            } => write!(
                f,
                "when decrypting, ciphertext of {ciphertext_len} bytes is too big, max is {max} \
                 bytes"
            ),
            Self::ConversionError(err) => write!(f, "failed to convert: {err}"),
            Self::DecryptionError => write!(f, "error during decryption"),
            Self::DeserializationEmptyError => {
                write!(f, "empty input when parsing bytes")
            }
            Self::DeserializationSizeError { given, expected } => write!(
                f,
                "wrong size when parsing bytes: {given} given should be {expected}"
            ),
            Self::EllipticCurveError(e) => write!(f, "NIST elliptic curve error: {e}"),
            Self::EncryptionError => write!(f, "error during encryption"),
            Self::GenericDeserializationError(err) => {
                write!(f, "deserialization error: {err}")
            }
            Self::GenericSerializationError(err) => {
                write!(f, "serialization error: {err}")
            }
            Self::InvalidBytesLength(message, given, expected) => match expected {
                Some(expected_length) => write!(
                    f,
                    "{message}: invalid key length: got {given}, expected: {expected_length}",
                ),
                None => {
                    write!(f, "{message}: invalid key length: got {given}")
                }
            },
            Self::PlaintextTooBigError { plaintext_len, max } => write!(
                f,
                "when encrypting, plaintext of {plaintext_len} bytes is too big, max is {max} \
                 bytes"
            ),
            #[cfg(any(feature = "certificate", feature = "nist_curves", feature = "rsa"))]
            Self::Pkcs8Error(err) => write!(f, "when converting to PKCS8, {err}"),
            Self::ReadLeb128Error(err) => write!(f, "when reading LEB128, {err}"),
            #[cfg(feature = "rsa")]
            Self::RsaError(e) => write!(f, "RSA error: {e}"),
            Self::DeserializationIoError { bytes_len, error } => {
                write!(f, "when reading {bytes_len} bytes, {error}")
            }
            Self::SerializationIoError { bytes_len, error } => {
                write!(f, "when writing {bytes_len} bytes, {error}")
            }
            Self::SignatureError(e) => write!(f, "error during signature: {e}"),
            Self::StreamCipherError(e) => write!(f, "stream cipher error: {e}"),
            Self::TryFromSliceError { expected, given } => {
                write!(
                    f,
                    "try from slice error: {given} was given when {expected} was expected"
                )
            }
            Self::WriteLeb128Error { value, error } => {
                write!(f, "when writing {value} as LEB128 size, IO error {error}")
            }
            Self::Shamir(str) => write!(f, "Shami secret sharing error: {str}"),
        }
    }
}

impl std::error::Error for CryptoCoreError {}

impl From<cosmian_crypto_base::Error> for CryptoCoreError {
    fn from(e: cosmian_crypto_base::Error) -> Self {
        Self::Base(e)
    }
}

#[cfg(feature = "aead")]
impl From<aead::Error> for CryptoCoreError {
    fn from(e: aead::Error) -> Self {
        Self::StreamCipherError(e.to_string())
    }
}

#[cfg(feature = "certificate")]
impl From<pkcs8::der::Error> for CryptoCoreError {
    fn from(e: pkcs8::der::Error) -> Self {
        Self::Pkcs8Error(e.to_string())
    }
}
#[cfg(any(feature = "certificate", feature = "nist_curves", feature = "rsa"))]
impl From<pkcs8::spki::Error> for CryptoCoreError {
    fn from(e: pkcs8::spki::Error) -> Self {
        Self::Pkcs8Error(e.to_string())
    }
}

#[cfg(any(feature = "certificate", feature = "nist_curves", feature = "rsa"))]
impl From<pkcs8::Error> for CryptoCoreError {
    fn from(e: pkcs8::Error) -> Self {
        Self::Pkcs8Error(e.to_string())
    }
}

#[cfg(any(feature = "certificate", feature = "nist_curves"))]
impl From<pkcs8::pkcs5::Error> for CryptoCoreError {
    fn from(e: pkcs8::pkcs5::Error) -> Self {
        Self::Pkcs8Error(e.to_string())
    }
}

#[cfg(feature = "certificate")]
impl From<x509_cert::builder::Error> for CryptoCoreError {
    fn from(e: x509_cert::builder::Error) -> Self {
        Self::Certificate(e.to_string())
    }
}

#[cfg(feature = "nist_curves")]
impl From<elliptic_curve::Error> for CryptoCoreError {
    fn from(e: elliptic_curve::Error) -> Self {
        Self::Certificate(e.to_string())
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::errors::Error> for CryptoCoreError {
    fn from(e: rsa::errors::Error) -> Self {
        CryptoCoreError::RsaError(e.to_string())
    }
}
