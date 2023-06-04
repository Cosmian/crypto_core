use core::fmt::Display;

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
    EncryptionError,
    GenericDeserializationError(String),
    InvalidKeyLength,
    PlaintextTooBigError {
        plaintext_len: usize,
        max: u64,
    },
    ReadLeb128Error(leb128::read::Error),
    SerializationIoError {
        bytes_len: usize,
        error: std::io::Error,
    },
    SignatureError(String),
    WriteLeb128Error {
        value: u64,
        error: std::io::Error,
    },
}

impl Display for CryptoCoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoCoreError::DeserializationEmptyError => {
                write!(f, "empty input when parsing bytes")
            }
            CryptoCoreError::DeserializationSizeError { given, expected } => write!(
                f,
                "wrong size when parsing bytes: {given} given should be {expected}"
            ),
            CryptoCoreError::ReadLeb128Error(err) => write!(f, "when reading LEB128, {err}"),
            CryptoCoreError::GenericDeserializationError(err) => {
                write!(f, "deserialization error: {err}")
            }
            CryptoCoreError::WriteLeb128Error { value, error } => {
                write!(f, "when writing {value} as LEB128 size, IO error {error}")
            }
            CryptoCoreError::SerializationIoError { bytes_len, error } => {
                write!(f, "when writing {bytes_len} bytes, {error}")
            }
            CryptoCoreError::PlaintextTooBigError { plaintext_len, max } => write!(
                f,
                "when encrypting, plaintext of {plaintext_len} bytes is too big, max is {max} \
                 bytes"
            ),
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
            CryptoCoreError::EncryptionError => write!(f, "error during encryption"),
            CryptoCoreError::DecryptionError => write!(f, "error during decryption"),
            CryptoCoreError::InvalidKeyLength => write!(f, "invalid key length"),
            CryptoCoreError::SignatureError(e) => write!(f, "error during signature: {e}"),
        }
    }
}

impl std::error::Error for CryptoCoreError {}
