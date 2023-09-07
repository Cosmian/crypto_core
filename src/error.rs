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
            Self::DeserializationEmptyError => {
                write!(f, "empty input when parsing bytes")
            }
            Self::DeserializationSizeError { given, expected } => write!(
                f,
                "wrong size when parsing bytes: {given} given should be {expected}"
            ),
            #[cfg(feature = "ser")]
            Self::ReadLeb128Error(err) => write!(f, "when reading LEB128, {err}"),
            Self::GenericDeserializationError(err) => {
                write!(f, "deserialization error: {err}")
            }
            Self::WriteLeb128Error { value, error } => {
                write!(f, "when writing {value} as LEB128 size, IO error {error}")
            }
            Self::SerializationIoError { bytes_len, error } => {
                write!(f, "when writing {bytes_len} bytes, {error}")
            }
            Self::PlaintextTooBigError { plaintext_len, max } => write!(
                f,
                "when encrypting, plaintext of {plaintext_len} bytes is too big, max is {max} \
                 bytes"
            ),
            #[cfg(any(feature = "certificate", feature = "nist_curves"))]
            Self::Pkcs8Error(err) => write!(f, "when converting to PKCS8, {err}"),
            #[cfg(any(feature = "certificate", feature = "nist_curves"))]
            Self::Certificate(err) => write!(f, "when build certificate, {err}"),
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
            Self::EncryptionError => write!(f, "error during encryption"),
            Self::DecryptionError => write!(f, "error during decryption"),
            Self::InvalidBytesLength(message, given, expected) => match expected {
                Some(expected_length) => write!(
                    f,
                    "{message}: invalid key length: got {given}, expected: {expected_length}",
                ),
                None => {
                    write!(f, "{message}: invalid key length: got {given}")
                }
            },
            Self::SignatureError(e) => write!(f, "error during signature: {e}"),
            Self::StreamCipherError(e) => write!(f, "stream cipher error: {e}"),
            Self::TryFromSliceError(e) => write!(f, "try from slice error: {e}"),
            #[cfg(feature = "nist_curves")]
            Self::EllipticCurveError(e) => write!(f, "NIST elliptic curve error: {e}"),
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
