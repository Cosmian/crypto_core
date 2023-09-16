use core::fmt::Display;
use std::array::TryFromSliceError;

/// Error type for this crate.
#[derive(Debug)]
pub enum CryptoCoreError {
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
    DeserializationSizeError {
        given: usize,
        expected: usize,
    },
    #[cfg(feature = "nist_curves")]
    EllipticCurveError(String),
    EncryptionError,
    GenericDeserializationError(String),
    InvalidBytesLength(String, usize, Option<usize>),
    PlaintextTooBigError {
        plaintext_len: usize,
        max: u64,
    },
    #[cfg(any(feature = "certificate", feature = "nist_curves"))]
    Certificate(String),
    #[cfg(any(feature = "certificate", feature = "nist_curves"))]
    Pkcs8Error(String),
    #[cfg(feature = "ser")]
    ReadLeb128Error(leb128::read::Error),
    #[cfg(feature = "enable-rsa")]
    RsaError(String),
    SerializationIoError {
        bytes_len: usize,
        error: std::io::Error,
    },
    SignatureError(String),
    StreamCipherError(String),
    TryFromSliceError(TryFromSliceError),
    WriteLeb128Error {
        value: u64,
        error: std::io::Error,
    },
}

impl Display for CryptoCoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(any(feature = "certificate", feature = "nist_curves"))]
            CryptoCoreError::Pkcs8Error(err) => write!(f, "when converting to PKCS8, {err}"),
            #[cfg(any(feature = "certificate", feature = "nist_curves"))]
            CryptoCoreError::Certificate(err) => write!(f, "when building certificate, {err}"),
            CryptoCoreError::Certificate(err) => write!(f, "when build certificate, {err}"),
            CryptoCoreError::CiphertextTooSmallError {
                ciphertext_len,
                min,
            } => write!(
                f,
                "when decrypting, ciphertext of {ciphertext_len} bytes is too small, min is {min} \
                 bytes"
            ),
            CryptoCoreError::CiphertextTooBigError {
                ciphertext_len,
                max,
            } => write!(
                f,
                "when decrypting, ciphertext of {ciphertext_len} bytes is too big, max is {max} \
                 bytes"
            ),
            CryptoCoreError::ConversionError(err) => write!(f, "failed to convert: {err}"),
            CryptoCoreError::DecryptionError => write!(f, "error during decryption"),
            CryptoCoreError::DeserializationEmptyError => {
                write!(f, "empty input when parsing bytes")
            }
            CryptoCoreError::DeserializationSizeError { given, expected } => write!(
                f,
                "wrong size when parsing bytes: {given} given should be {expected}"
            ),
            #[cfg(feature = "nist_curves")]
            CryptoCoreError::EllipticCurveError(e) => write!(f, "NIST elliptic curve error: {e}"),
            CryptoCoreError::EncryptionError => write!(f, "error during encryption"),
            CryptoCoreError::GenericDeserializationError(err) => {
                write!(f, "deserialization error: {err}")
            }
            CryptoCoreError::InvalidBytesLength(message, given, expected) => match expected {
                Some(expected_length) => write!(
                    f,
                    "{message}: invalid key length: got {given}, expected: {expected_length}",
                ),
                None => {
                    write!(f, "{message}: invalid key length: got {given}")
                }
            },
            CryptoCoreError::PlaintextTooBigError { plaintext_len, max } => write!(
                f,
                "when encrypting, plaintext of {plaintext_len} bytes is too big, max is {max} \
                 bytes"
            ),
            #[cfg(any(feature = "certificate", feature = "nist_curves"))]
            CryptoCoreError::Pkcs8Error(err) => write!(f, "when converting to PKCS8, {err}"),
            #[cfg(feature = "ser")]
            CryptoCoreError::ReadLeb128Error(err) => write!(f, "when reading LEB128, {err}"),
            #[cfg(feature = "enable-rsa")]
            CryptoCoreError::RsaError(e) => write!(f, "RSA error: {e}"),
            CryptoCoreError::SerializationIoError { bytes_len, error } => {
                write!(f, "when writing {bytes_len} bytes, {error}")
            }
            CryptoCoreError::SignatureError(e) => write!(f, "error during signature: {e}"),
            CryptoCoreError::StreamCipherError(e) => write!(f, "stream cipher error: {e}"),
            CryptoCoreError::TryFromSliceError(e) => write!(f, "try from slice error: {e}"),
            CryptoCoreError::WriteLeb128Error { value, error } => {
                write!(f, "when writing {value} as LEB128 size, IO error {error}")
            }
        }
    }
}

impl std::error::Error for CryptoCoreError {}

#[cfg(feature = "aead")]
impl From<aead::Error> for CryptoCoreError {
    fn from(e: aead::Error) -> Self {
        Self::StreamCipherError(e.to_string())
    }
}

impl From<TryFromSliceError> for CryptoCoreError {
    fn from(e: TryFromSliceError) -> Self {
        Self::TryFromSliceError(e)
    }
}

#[cfg(feature = "certificate")]
impl From<pkcs8::der::Error> for CryptoCoreError {
    fn from(e: pkcs8::der::Error) -> Self {
        Self::Pkcs8Error(e.to_string())
    }
}
#[cfg(any(feature = "certificate", feature = "nist_curves"))]
impl From<pkcs8::spki::Error> for CryptoCoreError {
    fn from(e: pkcs8::spki::Error) -> Self {
        Self::Pkcs8Error(e.to_string())
    }
}

#[cfg(any(feature = "certificate", feature = "nist_curves"))]
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
